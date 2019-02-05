// based on
// https://support.cloudbees.com/hc/en-us/articles/115000088431-Create-a-Matrix-like-flow-with-Pipeline

def targets = [ "main" ]
def tasks = [:]


for(int i=0; i < targets.size(); i++) {
	def targetValue = targets[i]
	tasks["${targetValue}"] = {
		node {
			def target = targetValue
			println "Building for ${target}"
			println "Node=${env.NODE_NAME}"
			agent { dockerfile true }
			checkout scm
			sh 'make TARGET=arm CC=arm-linux-gnueabihf-gcc-5 LD=arm-linux-gnueabihf-gcc-5 CROSS_USR=/usr'
		}
	}
}

stage ("Matrix") {
	parallel tasks
}
