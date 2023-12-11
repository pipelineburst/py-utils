# get imgages from ecr and print image name
import boto3
import kubernetes as k8s
import pandas as pd
import argparse

# resetting files
print("##############################################")
print("Let's get some info on our deployed images...")
print("##############################################")
print("Start resetting processing files...")
try:
    file = open("image_list.txt", "r+")
    file.truncate()
    file = open("image_list_uniq.txt", "r+")
    file.truncate()
    file = open("image_size.txt", "r+")
    file.truncate()
    file = open("image_size_sorted.txt", "r+")
    file.truncate()
    file = open("image_vulns.txt", "r+")
    file.truncate()
except Exception as e:
    file = open("image_list.txt", "w+")
    file = open("image_list_uniq.txt", "w+")
    file = open("image_size.txt", "w+")
    file = open("image_size_sorted.txt", "w+")
    file = open("image_vulns.txt", "w+")    
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
    hs.close()
print("Duplicates removed !")

#load file and remove non-mycom images from the list to be able to get the size of the images that are running on the k8s cluster
print("Removing non-mycom images from the list to be able to get the size of the images that are running on the k8s cluster")

with open('image_list_uniq.txt') as image_list:
    images = image_list.read().splitlines()
    hs = open("image_list_uniq.txt","w")
    for image in images:
        if "docker.mycom-osi.com" in image:
            hs.write(f"{image}" + "\n")
    hs.close()
print('Removed non-mycom images')

val = input("What do we need? Enter size or vulns: ")

if val == "size":

    region = 'eu-west-1'
    client = boto3.client('ecr')

    print("Now getting the image sizes from ECR")

    with open('image_list_uniq.txt') as container_list:
        containers = container_list.read().splitlines()
        try: 
            for container in containers:
                repo = container.replace("docker.mycom-osi.com/", "").split(":")[0]
                tag = container.split(":")[-1]
                response = client.describe_images(
                        repositoryName=repo,
                        imageIds=[
                            {
                                'imageTag': tag
                            },
                        ]
                )
                hs = open("image_size.txt","a")
                hs.write(f" {repo}:{tag} size = {round(int(response['imageDetails'][0]['imageSizeInBytes'])/1e6)} MB"  + "\n")
                hs.close() 
                print(f" {repo}:{tag} size = {round(int(response['imageDetails'][0]['imageSizeInBytes'])/1e6)} MB")
        except Exception as e:
            print("Oh no !")
            print(e)

    print("Done ! The image_size.txt file containes the image sizes for the running images on the k8s cluster")

    # sort the file image_size.txt by size
    print("Sorting the file image_size.txt by size")

    df = pd.read_csv("image_size.txt", sep=" ", header=None)
    df = df.sort_values(by=4, ascending=False)
    df.to_csv("image_size_sorted.txt", sep=" ", index=False, header=False)
    print("Done ! The image_size_sorted.txt file containes the image sizes for the running images on the k8s cluster")
    print("Happy Days :-)")

else:
    region = 'eu-west-1'
    client = boto3.client('ecr')

    print("Now getting the image vulns from ECR")

    with open('image_list_uniq.txt') as container_list:
        containers = container_list.read().splitlines()
        try: 
            critical = 0
            high = 0
            medium = 0
            low = 0
            for container in containers:
                repo = container.replace("docker.mycom-osi.com/", "").split(":")[0]
                tag = container.split(":")[-1]
                response = client.describe_image_scan_findings(
                        repositoryName=repo,
                        imageId={
                                'imageTag': tag
                        }
                )
                hs = open("image_vulns.txt","a")
                if 'findingSeverityCounts' in response['imageScanFindings']:
                    findings=response['imageScanFindings']['findingSeverityCounts']
                    hs.write(f" {repo}:{tag} vuln counts = {(findings)}" + "\n")
                    critical += findings.get('CRITICAL', 0)
                    high += findings.get('HIGH', 0)
                    medium += findings.get('MEDIUM', 0)
                    low += findings.get('LOW', 0)
                hs.close() 
                print(f'{repo} {tag} {findings}')
            print("##############################################")            
            print('Critical: ' + str(critical))
            print('High: ' + str(high))
            print('Medium: ' + str(medium))
            print('Low: ' + str(low))
            print("##############################################")  
        except Exception as e:
            print("Oh no !")
            print(e)