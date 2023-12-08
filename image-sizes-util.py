# get imgages from ecr and print image name
import boto3
import json
from botocore.exceptions import ClientError
import kubernetes as k8s

# resetting files
print("Let's get the images sizes")
print("Resetting processing files...")
try:
    file = open("image_list.txt", "r+")
    file.truncate()
    file = open("image_list_uniq.txt", "r+")
    file.truncate()
    file = open("image_size.txt", "r+")
    file.truncate()
except Exception as e:
    file = open("image_list.txt", "w+")
    file = open("image_list_uniq.txt", "w+")
    file = open("image_size.txt", "w+")
    print("clearing files")
print("Done with resetting files !")
    
# getting running container list from k8s cluster 
print("Getting running images from the k8s cluster")
print("Takes about 10s...")
k8s.config.load_kube_config()
v1 = k8s.client.CoreV1Api()
response_k8s = v1.list_namespaced_pod(namespace="eaa", watch=False)
for pod in response_k8s.items:
    hs = open("image_list.txt","a")
    hs.write(f"{pod.spec.containers[0].image}" + "\n")
    hs.close() 
print("Got the list !")

# load file as list and remove duplicates
print("Removing duplicates...")

with open('image_list.txt') as image_list:
    images = image_list.read().splitlines()
    images = list(dict.fromkeys(images))
    hs = open("image_list_uniq.txt","a")
    for image in images:
        hs.write(f"{image}" + "\n")
print("Duplicates removed !")

region = 'eu-west-1'
client = boto3.client('ecr')

print("Now getting the image sizes from ECR")

with open('image_list_uniq.txt') as container_list:
    containers = container_list.read().splitlines()
    try: 
        for container in containers:
            repo = container.replace("docker.mycom-osi.com/", "").split(":")[0]
            tag = container.split(":")[-1]
            print(f'Success for {repo} {tag}')
            response = client.describe_images(
                    repositoryName=repo,
                    imageIds=[
                        {
                            'imageTag': tag
                        },
                    ]
            )
            hs = open("image_size.txt","a")
            hs.write(f" {repo}:{tag} size = {round(int(response['imageDetails'][0]['imageSizeInBytes'])/1e6)} GB"  + "\n")
            hs.close() 
    except Exception as e:
        print("Oh no !")
        print(e)

print("Done ! The image_size.txt file containes the image sizes for the running images on the k8s cluster")
print("Happy Days :-)")