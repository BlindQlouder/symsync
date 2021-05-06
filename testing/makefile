

mkfolders:
	bash mkfolders.sh

run_blindpush:
	cd ..; env MYSYNCPATH=`pwd`/testing/pc1/local cargo run blindpush

run_blindpull:
	cd ..; env MYSYNCPATH=`pwd`/testing/pc2/local cargo run blindpull

run_update:
	cd ..; env MYSYNCPATH=`pwd`/testing/pc2/local cargo run update

run_rsync:
	rsync pc1/remote/* pc2/remote 

clean:
	rm -rf pc1 pc2


