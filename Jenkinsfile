pipeline {
	agent { label 'docker' }
	stages {
		stage ('Build') {
			agent {	dockerfile true }
			steps {
				sh 'make TARGET=arm CC=arm-linux-gnueabihf-gcc-5 LD=arm-linux-gnueabihf-gcc-5 CROSS_USR=/usr'
			}
		}
	}
}
