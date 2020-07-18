use std::env;
use std::path::{Path, PathBuf};

use symsync::*;


fn main() -> Result<()> {

	let usage_message = "usage: symsync <command>

commands:

    blindpull:  pull and decrypt everything, deleting what might have been in local folder

    blindpush:  encrypt and push everything, deleting what might have been in remote folder    
     
    update:     syncronize based on modification time of files. After an initial BlindPush or BlindPull, this should be the default command 
";

	let args: Vec<String> = env::args().collect();
	if args.len() < 2 {
		println!("{}", usage_message);
		return Ok(());
	}
	let goal;
	if &args[1] == "blindpush" {
		goal = Goal::BlindPush;
	} else if &args[1] == "blindpull" {
		goal = Goal::BlindPull;
	} else if &args[1] == "update" {
		goal = Goal::Update;
	} else {
		println!("{}", usage_message);
		return Ok(())
	}


	// cd to localdir
	match env::var("MYSYNCPATH") {
		Ok(home) => env::set_current_dir(home)?,
		Err(e) => {
			println!("could not read system variable MYSYNCPATH: {}", e);
			println!("Did you export MYSYNCPATH? This is the path to the folder that you want to sync.");
		}
	}
	
	let config = Config::load(Path::new(".sync/config.toml"))?;

	let mut jambon = Jambon::start(config, &goal)?;

	match goal {
		Goal::BlindPush => {
			let fnames = get_filenames(&PathBuf::from("."));
			for fname in fnames {
				println!("adding {:?}", &fname);
				jambon.encrypt_save_add(&fname)?;
			}
		}
		Goal::BlindPull => {
			jambon.load_missing()?;

		}
		Goal::Update => {
			let fnames = get_filenames(&PathBuf::from("."));
			for fname in &fnames {
				jambon.update(&fname)?;
			}
			jambon.load_missing()?;
			let fnames = get_filenames(&PathBuf::from("."));
			jambon.clean_image(&fnames)?;
			
		}
	}

	jambon.finish(&goal)?;

	Ok(())
}
