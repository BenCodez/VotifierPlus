SHELL := bash


.PHONY: all
all: build


.PHONY: build
build:
	./gradlew build


.PHONY: coveralls
coveralls:
	./gradlew jacocoTestReport coveralls


.PHONY: wrapper
wrapper:
	./gradlew wrapper
