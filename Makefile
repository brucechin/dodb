all:
	@echo "usage: make hardware_run/software_run"

prepare: clean
	mkdir ./build
	cd ./build; wget "https://raw.githubusercontent.com/SabaEskandarian/ObliDB/master/rankings.csv"; wget "https://raw.githubusercontent.com/SabaEskandarian/ObliDB/master/uservisits.csv"

hardware_run: prepare hardware_mode run

software_run: prepare software_mode run

hardware_mode:
	cd build; cmake -DSGX_HW=ON -DSGX_MODE=Release ..; make

software_mode:
	cd build; cmake ..; make

run:
	cd build; ./App

clean:
	rm -Rf ./build
