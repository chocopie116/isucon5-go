build:
	go build -o app
run:
	export GOGC=1000;go run app.go
start:
	export GOGC=1000; sudo systemctl start isuxi.go
stop:
	sudo systemctl stop isuxi.go
