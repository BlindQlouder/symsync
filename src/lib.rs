//! Symmetric Synchronization of folders on different machines over an untrusted server. 
//!
//! On every machine there are two folders, `remote` and `local`. The `remote` folder contains the
//! encrypted and signed files that can be copied to the untrusted server. The names of the files are hashed
//! and their sizes are masked by a random amount of bytes. All information about the files are
//! stored in an encrypted image-file, such that we only update files that have changed. The
//! `local` folder contains the unencrypted files on which you work normally. Ones you are done you
//! run `symsync update`.
//!
//! To synchronize the `remote` folder with the server, you need to specify the commands in the
//! config file, which is located in .sync/ in the `local` folder. 
//!
//! This is the first working version... So no garantee for your files. Please make a backup
//! regularly. 



use std::fs::{self, File};
use std::env;
use std::path::{Path, PathBuf};
use std::io::{self, Read, Write};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::fmt;
use std::convert::TryFrom;
use std::process::Command;
use std::ffi::{OsString, OsStr};

use std::time::{UNIX_EPOCH, SystemTime};

use openssl::symm::{encrypt, decrypt, Cipher};
use openssl::rand::rand_bytes;

//use sha3::{Sha3_256, Digest};

use toml;
use serde::{Serialize, Deserialize};
use serde;

use rand;
use rand_distr::{Exp, Distribution};


const L_KEY: usize = 32;        // size of the key
const L_IV: usize = 16;         // size of the initial vector needed for AES

type Key = [u8; L_KEY];
type Iv = [u8; L_IV];

static FOLDER_SYNC: &str = ".sync";
static IMAGE_LOCAL: &str = "image.toml";
static IMAGE_REMOTE: &str = "image";

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;



/// Signature error.
struct SigError;

impl fmt::Display for SigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Signature mismatch!")
    }
}
impl fmt::Debug for SigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Signature mismatch! Someone might have tempered with your data.")
    }
}
impl std::error::Error for SigError {
    fn description(&self) -> &str {
        "Signature mismatch! Someone might have tempered with your data."
    }
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // Generic error, underlying cause isn't tracked.
        None
    }
}

/// The task of the program
pub enum Goal {
	/// encrypt and push everything, deleting what might have been in remote folder.
	BlindPush,
	/// pull and decrypt everything, deleting what might have been in local folder.
	BlindPull,
	/// syncronizes based on modification time of files. After an initial BlindPush or BlindPull, this is the default task
	Update,
}

/// User configurations read from .sync/config.toml
#[derive(Deserialize, Debug)]
pub struct Config {
	key_hex: String,
	#[serde(skip)]
	key: Key, 				// converted from key_hex
	gpath: PathBuf,
	command_push: String,
	command_pull: String,
}

impl Config {
	fn hex_to_key(s: &String) -> Result<Key> {
	let l = s.len()/2;
	let mut key: Key = [0; L_KEY];
	for i in 0..l {
		let b = &s[2*i..2*i+2];
		key[i] = u8::from_str_radix(b, 16)?;
	}
	Ok(key)
}

	/// load the configuration from file
	///
	/// # Example
	///
	/// ```no_run
	/// use symsync::Config;
	/// use std::path::Path;
	/// 
	/// let config = Config::load(Path::new(".sync/config.toml"))?;
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn load(fname: &Path) -> Result<Self> {
		let mut f = File::open(&fname)?;
		let mut config_string = String::new();
		f.read_to_string(&mut config_string)?;
		let mut config: Config = toml::from_str(&config_string)?;
		config.key = Config::hex_to_key(&config.key_hex)?;
		Ok(config)
	}
}


/// Info about a single file. 
#[derive(Serialize, Deserialize, Debug, Clone)]
struct Metadata {
	name: String,	 		// path and name of the file
	namehash: String,		// hashed name
	modified: u64, 			// modification time in seconds since the epoche; this can as well be the time of the last pull
	actually_modified: u64, // time the file was actually modified
	signature: String, 		// Signature of the file (from SipHash)
	iv: Iv,		 			// IV used for encryption
}


/// Image of the filesystem excluding the actual content of the files. 
/// Basically a collection of Metadata.
#[derive(Serialize, Deserialize, Debug)]
struct Image {
	last_update: u64, 					// time of last sync
	siphashkey: [u8; 32],				// key used for the namehash
	filesystem: Vec<Metadata>,
}

/// Structure to compare the local and remote images and operate on them for encryption, decryption etc.
pub struct Jambon {
	image_l: Option<Image>, 		// local image
	image_r: Option<Image>, 		// remote image
	gpath: PathBuf, 				// path to remote image
	key: Key, 						// key from config
	command_push: String, 			// push command form config
	did_something: bool, 			// for not copying the image if nothing was updated
}

impl Image {
	/// create an Image instance and calculate a random key for namehashing 
	/// (the encryption key from the config file has nothing to do with this)
	fn new() -> Self {
		let image = Image {
			filesystem: Vec::new(),
			last_update: 0,
			siphashkey: gen_key(),
		};
		image
	}
	/// load Image from toml in clear format. 
	fn from_local() -> Result<Self> {
		let path: PathBuf = [FOLDER_SYNC, IMAGE_LOCAL].iter().collect();
		let mut f = File::open(path)?;
		let mut string = String::new();
		f.read_to_string(&mut string)?;
		let image: Image = toml::from_str(&string)?;
		Ok(image)
	}
	/// load Image from toml in encrypted format. 
	fn from_remote(gpath: &Path, key: &Key) -> Result<Self> {
		let mut path = PathBuf::from(gpath);
		path.push(IMAGE_REMOTE);
		let mut f = File::open(path)?;
		let mut buf = Vec::new();
		f.read_to_end(&mut buf)?;
		let l = buf.len();
		let iv = Iv::try_from(&buf[l-L_IV..])?;
		let message = my_decrypt(&buf[..l-L_IV], &key, &iv)?;
		let message = String::from_utf8(message)?;
		let image: Image = toml::from_str(&message)?;
		Ok(image)
	}

	/// add a file to Image. This will calculate the hashed name and signature of the file. 
	/// It will also check when the file was last modified
	fn push(&mut self, filename: &Path, content: &Vec<u8>, iv: Iv) -> io::Result<&mut Self> {
		let attr = fs::metadata(&filename)?;
		let modtime = attr.modified().unwrap().duration_since(UNIX_EPOCH).unwrap().as_secs();
		let meta = Metadata {
			name: filename.to_str().unwrap().to_string(),
			namehash: format!("{:x}", calc_signature_sip(&filename, &self.siphashkey)),
			modified: modtime,
			actually_modified: modtime.clone(),
			signature: format!("{:x}", calc_signature_sip(&content, &self.siphashkey)),
			iv: iv,//slice_to_hex(&iv[..]),
		};
		self.filesystem.push(meta);
		self.last_update = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
		Ok(self)
	}
	
	/// update the metadata of an existing entry
	fn update(&mut self, filename: &Path, content: &Vec<u8>, iv: Iv, idx: usize) -> io::Result<&mut Self> {
		let attr = fs::metadata(&filename)?;
		let modtime = attr.modified().unwrap().duration_since(UNIX_EPOCH).unwrap().as_secs();
		let meta = Metadata {
			name: filename.to_str().unwrap().to_string(),
			namehash: format!("{:x}", calc_signature_sip(&filename, &self.siphashkey)),
			modified: modtime,
			actually_modified: modtime.clone(),
			signature: format!("{:x}", calc_signature_sip(&content, &self.siphashkey)),
			iv: iv,//slice_to_hex(&iv[..]),
		};
		self.filesystem[idx] = meta;
		self.last_update = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
		Ok(self)
	}

	/// change the siphashkey. This is in case there is a conflict between the remote and local siphashkey. 
	/// This happens after blindpush because a new siphashkey gets generated.
	fn update_siphashkey(&mut self, skey: &Key) {
		self.siphashkey = skey.clone();
		for mut metadata in &mut self.filesystem {
			metadata.namehash = format!("{:x}", calc_signature_sip(&metadata.name, &self.siphashkey));
		}
		
	}

	/// save Image as toml in clear format to local folder
	fn save_local(&self) -> Result<()>{
		let toml = toml::to_string(&self)?;
		let path: PathBuf = [FOLDER_SYNC, IMAGE_LOCAL].iter().collect();
		let mut f = File::create(path)?;
		f.write_all(toml.as_bytes())?;
		Ok(())
	}
	
	/// save Image as toml in encrytped format to remote folder
	fn save_remote(&self, gpath: &Path, key: &Key) -> Result<()> {
		let toml = toml::to_string(&self)?;
		let (mut cipher, iv) = my_encrypt(&toml.as_bytes(), key)?;
		cipher.extend(&iv);
		let mut path = PathBuf::from(&gpath);
		path.push(IMAGE_REMOTE);
		let mut f = File::create(path)?;
		f.write_all(&cipher)?;
		Ok(())
	}

	/// return the index at which file fname is stored. None if there is no such file.
	fn get_index(&self, fname: &Path) -> Option<usize> {
		for i in 0..self.filesystem.len() {
			if fname.to_str().unwrap() == self.filesystem[i].name {
				return Some(i)
			}
		}
		None
	}

	/// return a list of all filenames in Image
	fn get_filenames(&self) -> Vec<PathBuf> {
		let mut files = Vec::new();
		for metadata in &self.filesystem {
			let file = PathBuf::from(&metadata.name);
			files.push(file);
		}
		files
	}
	
	/// return a list of all hashed filenames in Image
	fn get_hashnames(&self) -> Vec<PathBuf> {
		let mut files = Vec::new();
		for metadata in &self.filesystem {
			let file = PathBuf::from(&metadata.namehash);
			files.push(file);
		}
		files
	}
}


/// The main implementation that does everything. 
///
/// # Example (this is basically the entire main)
///
/// ```no_run
///
/// use symsync::{Config, Jambon, Goal, get_filenames};
/// use std::path::{Path, PathBuf}; 
///
/// // load the configuration file
/// let config = Config::load(Path::new(".sync/config.toml"))?;
///
/// // set task to update for this example
/// let goal = Goal::Update;
///
///	let mut jambon = Jambon::start(config, &goal)?;
///
///	match goal {
///		Goal::BlindPush => {
///			let fnames = get_filenames(&PathBuf::from("."));
///			for fname in fnames {
///				println!("adding {:?}", &fname);
///				jambon.encrypt_save_add(&fname)?;
///			}
///		}
///		Goal::BlindPull => {
///			jambon.load_missing(&Vec::new())?;
///		}
///		Goal::Update => {
///			let fnames = get_filenames(&PathBuf::from("."));
///			for fname in &fnames {
///				jambon.update(&fname)?;
///			}
///			jambon.clean_image(&fnames)?;
///			jambon.load_missing(&fnames)?;
///		}
///	}
///
///	jambon.finish(&goal)?;
///
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```

impl Jambon {
	/// load the images, run `command_pull`, update siphashkey if necessary
	pub fn start(config: Config, goal: &Goal) -> Result<Self> {
		let key = config.key; 
		let gpath = config.gpath;
		let mut image_l;
		let image_r;
		match goal {
			Goal::BlindPush => {
				Jambon::cleangpath(&gpath)?;
				image_l = Some(Image::new());
				image_r = None;
			}
			Goal::BlindPull => {
				Jambon::gpull(&gpath, &config.command_pull)?;
				image_r = Some(Image::from_remote(&gpath, &key)?);
				let mut image = Image::new();
				image.siphashkey = image_r.as_ref().unwrap().siphashkey.clone();
				image_l = Some(image);

			}
			Goal::Update => {
				Jambon::gpull(&gpath, &config.command_pull)?;
				image_l = Some(Image::from_local()?);
				image_r = Some(Image::from_remote(&gpath, &key)?);
				if image_l.as_ref().unwrap().siphashkey != image_r.as_ref().unwrap().siphashkey {
					println!("Problem: Siphashkey (for hashing the filenames) differs between remote and local. \
						Probably because you did blindpush, which regenerates the siphashkey. \
						Do you want to continue with the new remote siphashkey? This is recommended. [Y/n]");
					let mut buf = String::new();
					io::stdin().read_line(&mut buf)?;
					if (buf == "y\n") || (buf == "Y\n") || (buf == "\n") {
						println!("updating local siphashkey with the remote one");
						image_l.as_mut().unwrap().update_siphashkey(&image_r.as_ref().unwrap().siphashkey);
					} else if (buf == "n\n") || (buf == "N\n") {
						return Err("not really an error. Just exiting.".into());
					} else {
						println!("wrong input");
						return Err("not really an error. Just exiting".into());
					}
				}
			}
		}
		let jambon = Jambon {
			image_l: image_l,
			image_r: image_r,
			gpath: gpath,
			key: key,
			command_push: config.command_push,
			//command_pull: config.command_pull,
			did_something: false,
		};
		Ok(jambon)
	}

	/// encrypt file, save it to `remote` and add entry to `image_l`
	pub fn encrypt_save_add(&mut self, fname: &Path) -> Result<&mut Self> {
		let content = readfile(&fname)?;
		let (cipher, iv) = my_encrypt(&content, &self.key)?;
		let image = self.image_l.as_mut().ok_or("local image is none")?;
		let getidx = image.get_index(&fname);
		let namehash;
		match getidx {
			Some(idx) => {
				image.update(&fname, &content, iv, idx)?;
				namehash = &image.filesystem[idx].namehash;
			}
			None => {
				image.push(&fname, &content, iv)?;
				namehash = &image.filesystem.last().unwrap().namehash;
				}
		}
		let mut path = PathBuf::from(&self.gpath);
		path.push(namehash);
		writefile(&path, &cipher)?;
		Ok(self)
	}

	/// this function performs one of three actions on file fname based on its modification time
	/// - action1: encrypt, save in `remote` and update `image_l`
	/// - action2: decrypt, check signature, save in `local` and update `image_l`
	/// - action3: delete file in `local` and delete entry in `image_l`
	///
	/// it tries to detect some possible conflicts but it is far from idiot proof
	pub fn update(&mut self, fname: &Path) -> Result<&mut Self> {
		let attr = fs::metadata(&fname)?;
		let modtime = attr.modified().unwrap().duration_since(UNIX_EPOCH).unwrap().as_secs();
		let getidx_l = self.image_l.as_ref().unwrap().get_index(&fname);
		let getidx_r = self.image_r.as_ref().unwrap().get_index(&fname);
		match getidx_l {
			Some(idx_l) => {
				let modtime_l = self.image_l.as_ref().unwrap().filesystem[idx_l].modified;
				let modtime_la = self.image_l.as_ref().unwrap().filesystem[idx_l].actually_modified;
				match getidx_r {
					Some(idx_r) => {
						// file in both local and remote image
						//let modtime_r = self.image_r.as_ref().unwrap().filesystem[idx_r].modified;
						let modtime_ra = self.image_r.as_ref().unwrap().filesystem[idx_r].actually_modified;
						if modtime > modtime_l { 
							// file has been locally modified since the last pull or push
							if modtime_la < modtime_ra {
								println!("problem with {:?}: file was updated both locally and remotely", fname);
                                let mut fname_backup = OsString::from(fname);
                                fname_backup.push("_local_backup");
							    fs::rename(&fname, &fname_backup)?;
							    //println!("action2 (decrypt, save, update image entry {:?}", &fname);
							    Self::decrypt_save_add(
							    	self.image_l.as_mut().unwrap(),
							    	&self.image_r.as_ref().unwrap().filesystem[idx_r],
							    	&self.gpath,
							    	&self.key,
							    	&self.image_r.as_ref().unwrap().siphashkey)?;
							    self.did_something = true;
								println!("file {:?} was pulled and the local file backed up as {:?}", &fname, &fname_backup);
								println!("please manually merge the two files and run update again!");
							}
                            else {
							    println!("action1 (encrypt, save, update image entry) {:?}", &fname);
							    self.encrypt_save_add(&fname)?;
							    self.did_something = true;
                            }
						}
						else if modtime_la < modtime_ra {
							println!("action2 (decrypt, save, update image entry {:?}", &fname);
							Self::decrypt_save_add(
								self.image_l.as_mut().unwrap(),
								&self.image_r.as_ref().unwrap().filesystem[idx_r],
								&self.gpath,
								&self.key,
								&self.image_r.as_ref().unwrap().siphashkey)?;
							self.did_something = true;
						}

					}
					None => {
						// file in local image only
						if modtime < self.image_r.as_ref().unwrap().last_update {
							println!("action3 (delete file and entry in local image {:?})", &fname);
							fs::remove_file(&fname)?;
							self.image_l.as_mut().unwrap().filesystem.remove(idx_l);
							self.image_l.as_mut().unwrap().last_update = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
							self.did_something = true;
						}
					}
				}
			}
			None => {
				match getidx_r {
					Some(_idx_r) => {
						// file in remote image only
						println!("problem with {:?}: file was created locally even though it existed remotely", &fname);
					}
					None => {
						// file not in images
						println!("action1 (encrypt, save, update image entry) {:?}", &fname);
						self.encrypt_save_add(&fname)?;
						self.did_something = true;
					}
				}
			}
		}		
		Ok(self)
	}

	/// if files are in remote and not in local:
	/// - action2: decrypt, check signature, save in `local` and update `image_l`
	pub fn load_missing(&mut self) -> Result<&mut Self> {
		let fsystem_r = &self.image_r.as_ref().unwrap().filesystem;
		let fnames_l = self.image_l.as_ref().unwrap().get_filenames();
		for i in 0..fsystem_r.len() {
			let fname_r = &fsystem_r[i].name;
			if fnames_l.iter().find(|&fname| fname_r==fname.to_str().unwrap()).is_none() {
				println!("load missing; action2 (decrypt, save, add) file {:?}", &fname_r);
				Self::decrypt_save_add(
					self.image_l.as_mut().unwrap(),
					&fsystem_r[i],
					&self.gpath,
					&self.key,
					&self.image_r.as_ref().unwrap().siphashkey)?;
                self.did_something = true;
			}
		}
		Ok(self)
	}

	/// if a file is not in local but in local image:
	/// - action4: delete entry in local image
	pub fn clean_image(&mut self, fnames: &Vec<PathBuf>) -> Result<&mut Self> {
		let fnames_l = self.image_l.as_ref().unwrap().get_filenames();
		for fname_l in fnames_l {
			if fnames.iter().find(|&fname| &fname_l==fname).is_none() {
				println!("action4 (remove from image) file {:?}", &fname_l);
				let idx = self.image_l.as_ref().unwrap().get_index(&fname_l).unwrap();
				self.image_l.as_mut().unwrap().filesystem.remove(idx);
				self.image_l.as_mut().unwrap().last_update = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
				self.did_something = true;
			}
		}
		Ok(self)
	}

	/// if after update files are in remote but not in local image:
	/// - action5: delete file from remote
	pub fn clean_remote(&self) -> Result<&Self> {
		let fnames_r = get_filenames(&self.gpath);
		let fnames_l = self.image_l.as_ref().unwrap().get_hashnames();
		for fname_r in fnames_r {
			if fnames_l.iter().find(|&fname_l| &fname_r.file_name().unwrap()==fname_l).is_none() {
				if fname_r.file_name().unwrap() != "image" {
					println!("action5 (deleting file from remote) file {:?}", &fname_r);
					fs::remove_file(&fname_r)?;
				}
			}
		}
		Ok(self)
	}

	/// save image files to local and remote and run `command_push`
	pub fn finish(&self, goal: &Goal) -> Result<()> {
		match goal {
			Goal::BlindPush => {
				self.image_l.as_ref().unwrap().save_local()?;
				self.image_l.as_ref().unwrap().save_remote(&self.gpath, &self.key)?;
				self.gpush()?;
			}
			Goal::BlindPull => { 
				self.image_l.as_ref().unwrap().save_local()?;
			}
			Goal::Update => {
				if self.did_something {
					self.image_l.as_ref().unwrap().save_local()?;
					self.image_l.as_ref().unwrap().save_remote(&self.gpath, &self.key)?;
					self.clean_remote()?;
					self.gpush()?;
				} else {
					println!("nothing to be done");
				}	
			}
		}
		Ok(())
		
	}

	/// action2
	fn decrypt_save_add(
		image_l: &mut Image, 
		metadata: &Metadata, 
		gpath: &Path, 
		key: &Key,
		siphashkey: &Key) -> Result<()> {
		
		let mut path = PathBuf::from(&gpath);
		path.push(&metadata.namehash);
		let content = readfile(&path)?;
		let message = my_decrypt(&content, &key, &metadata.iv)?;
		check_signature(&metadata.signature, &message, &siphashkey)?;
		let path = PathBuf::from(&metadata.name);
		let getidx = image_l.get_index(&path);
		writefile(&path, &message)?;
		let attr = fs::metadata(&metadata.name)?;
		let modtime = attr.modified().unwrap().duration_since(UNIX_EPOCH).unwrap().as_secs();
		match getidx {
			Some(idx) => {
				image_l.filesystem[idx] = metadata.clone();
				image_l.filesystem[idx].modified = modtime;
			}
			None => {
				image_l.filesystem.push(metadata.clone());
				image_l.filesystem.last_mut().unwrap().modified = modtime;
			}
		}
		Ok(())
	}

	/// delete evything in gpath after user ok
	fn cleangpath(gpath: &Path) -> Result<()> {
		match fs::read_dir(&gpath) {
			Ok(mut iterator) => {
				if iterator.next().is_some() {
					// delete content
					println!("gpath not empty. Do you want to delete everything in it? [Y/n]");
					let mut buf = String::new();
					io::stdin().read_line(&mut buf)?;
					if (buf == "y\n") || (buf == "Y\n") || (buf == "\n") {
						println!("deleting files in {:?}", &gpath);
						fs::remove_dir_all(&gpath)?;
					} else if (buf == "n\n") || (buf == "N\n") {
						return Err("not really an error. Just exiting".into());
					} else {
						println!("wrong input");
						return Err("not really an error. Just exiting".into());
					}
				}
				return Ok(())
			}
			Err(_e) => {return Ok(())}
		}
	}

	/// run connand_pull
	fn gpull(gpath: &Path, command_pull: &str) -> Result<()> {
		let home = env::current_dir()?;
		if let Err(_e) = env::set_current_dir(&gpath) {
			println!("creating dir {:?}", &gpath);
			fs::create_dir(&gpath)?;
		}
		let command_pull = &command_pull.clone();
		let mut command_iter = command_pull.splitn(2, ' ');
		let mut args = "".to_string();
		let prog = command_iter.next().unwrap().to_string();
		if let Some(i) = command_iter.next() {args = i.to_string()}
		//println!("executing command {:?}...", &command_pull);
		let mut command = Command::new(prog).arg(args).spawn()?;
		command.wait()?;
		env::set_current_dir(home)?;
		Ok(())
	}

	/// run command_push
	fn gpush(&self) -> Result<()> {
		let home = env::current_dir()?;
		if let Err(_e) = env::set_current_dir(&self.gpath) {
			println!("creating dir {:?}", &self.gpath);
			fs::create_dir(&self.gpath)?;
		}
		let command_push = &self.command_push.clone();
		let mut command_iter = command_push.splitn(2, ' ');
		let mut args = "".to_string();
		let prog = command_iter.next().unwrap().to_string();
		if let Some(i) = command_iter.next() {args = i.to_string()}
		//println!("executing command {:?}...", &command_push);
		let mut command = Command::new(prog).arg(args).spawn()?;
		command.wait()?;
		env::set_current_dir(home)?;
		Ok(())
	}
}


/// get all the filenames in given directory and all subdirectories, ignoring the folder .sync
///
/// # Example
///
/// ```
/// use std::path::PathBuf;
/// use symsync::get_filenames;
/// 
/// let path = PathBuf::from(".");
/// let files = get_filenames(&path);
/// println!("these are all your files: {:?}", files);
/// ```
pub fn get_filenames(dir: &PathBuf) -> Vec<PathBuf> {
	let entries = fs::read_dir(&dir).expect("error in get_filenames trying to read_dir");
	let mut files = Vec::new();
	for e in entries {
		let path = e.unwrap().path();
		if path.is_dir() {
			if path.file_name().unwrap()==".sync" {
				continue;
			}
			files.append(&mut get_filenames(&path));
		} else {
			files.push(path);
		}
	}
    files.sort();
    files
}


/// read a file and return its content
fn readfile(fname: &Path)-> io::Result<Vec<u8>> {
	let mut f = File::open(fname)?;
	let mut buffer = Vec::new();
	f.read_to_end(&mut buffer)?;
	Ok(buffer)
}

/// write content to file
fn writefile(fname: &Path, content: &[u8]) -> io::Result<()> {
	let f = File::create(fname);
	match f {
		Ok(mut file) => {
			file.write_all(&content)?;
			}
		Err(_e) => {
			let folder = fname.parent().expect("error in writefile trying to get parent of fname");
			fs::create_dir(&folder)?;
			writefile(&fname, &content)?;
			}
		}
	Ok(())
}




/// generate an IV (initial vector for aes)
fn gen_iv() -> Iv {
	let mut buf: Iv = [0; L_IV];
	rand_bytes(&mut buf).unwrap();
	buf
}

/// generate a Key (to be used as siphashkey)
fn gen_key() -> Key {
	let mut buf: Key = [0; L_KEY];
	rand_bytes(&mut buf).unwrap();
	buf
}

fn gen_obfuscation() -> Vec<u8>{
    let exp = Exp::new(0.005).unwrap();
    let l = exp.sample(&mut rand::thread_rng()) as usize + 3;
    //println!("length: {:?}", l);
    let mut v = Vec::with_capacity(l);
    v.resize(l, 0);
    v[l-3] = (l>>16) as u8;
    v[l-2] = (l>>8) as u8;
    v[l-1] = l as u8;
    return v
}




/// encrypt a message with aes_256_cbc. A random number of zeros is appended to the message to hide
/// its length. This number is saved in the last entries of the new message.
/// Return the encrypted message and the initial vector (IV). 
/// The IV is needed for decryption of the first 16 bytes and can be public
fn my_encrypt(message: &[u8], key: &Key) -> Result<(Vec<u8>, Iv)> {
	let iv = gen_iv();
    let ob = gen_obfuscation();
    let new_message = [message, &ob].concat();
    //println!("length of new_message: {:?}", new_message.len());
	let cipher = Cipher::aes_256_cbc();
	let ciphertext = encrypt(cipher, &key[..], Some(&iv), &new_message)?;
    //println!("length of ciphertext: {:?}", ciphertext.len());
	Ok((ciphertext, iv))
}

/// decrypt a message with aes_256_cbc. 
fn my_decrypt(ciphertext: &[u8], key: &Key, iv: &Iv) -> Result<Vec<u8>> {
	let cipher = Cipher::aes_256_cbc();
	let mut message = decrypt(cipher, &key[..], Some(&iv[..]), &ciphertext)?;
    let l = message.len();
    let o1: usize = message[l-3].into();
    let o2: usize = message[l-2].into();
    let o3: usize = message[l-1].into();
    let oblen = (o1<<16) + (o2<<8) + o3;
    message.truncate(l-oblen);
	Ok(message)
}


// fn calc_signature_sha3(message: &Vec<u8>, key: &Key) -> [u8; 32] {
// 	let mut hasher = Sha3_256::new();
// 	hasher.input(&message);
// 	hasher.input(&key);
// 	let result = hasher.result().into();
// 	result
// }

fn calc_signature_sip<T: Hash>(message: &T, key: &Key) -> u64 {
	let mut s = DefaultHasher::new();
	&message.hash(&mut s);
	&key.hash(&mut s);
	s.finish()
}


/// calculate the signature of message and compare with given signature
/// Throw an SigError if they do not match.
fn check_signature(signature: &str, message: &Vec<u8>, siphashkey: &Key) -> Result<()> {
	let s = format!("{:x}", calc_signature_sip(&message, &siphashkey));
	if signature == s {Ok(())}
	else {Err(SigError.into())}
}


// convert array of numbers to hexadecimal string. 
// fn slice_to_hex<T: fmt::LowerHex>(a: &[T]) -> String {
// 	let mut s = String::new();
// 	for entry in a.iter() {
// 		s = s + &format!("{:x}", entry);
// 	}
// 	s
// }

// convert hexadecimal string to vector of u8 integers. 
// fn hex_to_u8vec(s: &String) -> Result<Vec<u8>> {
// 	let l = s.len()/2;
// 	let mut result = Vec::new();
// 	for i in 0..l {
// 		let b = &s[2*i..2*i+2];
// 		result[i] = u8::from_str_radix(b, 16)?;
// 	}
// 	Ok(result)
// }



#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	//fn test_keygen() -> Result<()> {
	//	let priv_path = Path::new(".");
	//	let pub_path = Path::new(".");
	//	keymanagement::gen_pub_priv_pair(&priv_path, &pub_path)?;
	//	Ok(())
	//}

    fn hello(){
        //let a = vec!(1,2,3,4);
        assert_eq!(2,2);
    }

    #[test]
    fn append_string_to_path(){
        let p = Path::new("test.txt");
        let mut p_copy = OsString::from(p);
        p_copy.push("_backup");
        assert_eq!(p_copy, OsString::from("test.txt_backup"));
        //assert_eq!(p_copy.push(OsStr::new("x")), OsStr::new("test.txtx"));
    }
}












