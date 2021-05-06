
all: mkfolders run_blindpush run_rsync run_blindpull run_update run_rsync2 run_update2



mkfolders:
	bash mkfolders.sh

run_blindpush:
	cd ..; \
		env MYSYNCPATH=`pwd`/testing/pc1/local cargo run blindpush

run_blindpull:
	cd ..; \
		env MYSYNCPATH=`pwd`/testing/pc2/local cargo run blindpull

run_update:
	cd ..; \
		mkdir -p testing/pc2/local/f2/g2; \
		echo "change on pc2" > testing/pc2/local/f2/g2/bla.txt; \
		env MYSYNCPATH=`pwd`/testing/pc2/local cargo run update

run_update2:
	cd ..; \
		env MYSYNCPATH=`pwd`/testing/pc1/local cargo run update

run_rsync:
	rsync pc1/remote/* pc2/remote 

run_rsync2:
	rsync pc2/remote/* pc1/remote 

clean:
	rm -rf pc1 pc2


