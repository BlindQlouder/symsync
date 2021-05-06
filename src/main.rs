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
		Ok(home) => {env::set_current_dir(&home).expect(format!("cannot go to directory {:?}", &home).as_str())}
		Err(e) => {
			println!("could not read system variable MYSYNCPATH: {}", e);
			println!("Did you export MYSYNCPATH? This is the path to the folder that you want to sync.");
		}
	}
	
	let config = Config::load(Path::new(".sync/config.toml")).expect("could not load config file");

	let mut jambon = Jambon::start(config, &goal).expect("Jambon::start in main() returned errer");

	match goal {
		Goal::BlindPush => {
			let fnames = get_filenames(&PathBuf::from("."));
			for fname in fnames {
				println!("adding {:?}", &fname);
				jambon.encrypt_save_add(&fname).expect("jambon.encrypt_save_add in main () returned error");
			}
		}
		Goal::BlindPull => {
			jambon.load_missing().expect("jambon.load_missing() in main() failed");

		}
		Goal::Update => {
			let fnames = get_filenames(&PathBuf::from("."));
			for fname in &fnames {
				jambon.update(&fname).expect("jambon.update() in main() returned error");
			}
			jambon.load_missing().expect("jambon.load_missing() in main() returned error");
			let fnames = get_filenames(&PathBuf::from("."));
			jambon.clean_image(&fnames).expect("jambon.clean_image() in main() returned error");
			
		}
	}

	jambon.finish(&goal).expect("jamobn.finish() in main() returned error");

	Ok(())
}
