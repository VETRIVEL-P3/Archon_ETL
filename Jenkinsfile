pipeline {
  agent any
  stages {
    stage('git clone') {
      steps {
        echo 'clone the repo'
      }
    }

    stage('Build') {
      steps {
        sh '''echo PATH = ${PATH}
mvn -N io.takari:maven:wrapper 
./mvnw clean install'''
      }
    }

    stage('Docker build') {
      steps {
        sh '''docker login docker-registry2.platform3solutions.com/archon --username akhilkottedi --password @kH!1@142
docker build . -t archon/authentication-service
NOW=$(date +"%m%d%y")
echo $NOW
docker tag archon/authentication-service docker-registry2.platform3solutions.com/archon/archon-authentication-service:3.1.$NOW
docker push docker-registry2.platform3solutions.com/archon/archon-authentication-service:3.1.$NOW'''
      }
    }

    stage('Build Status') {
      steps {
        office365ConnectorSend 'https://outlook.office.com/webhook/9245baf4-b8b3-40e2-b362-2f202569dd94@950af411-a869-4fdb-be85-926dbabe3c4f/JenkinsCI/c10d89cf20e841e3840bc651cfa7de28/57a0973b-ed7a-42b1-bfb0-dfa7b8408aa3'
      }
    }

  }
}
