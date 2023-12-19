#!/usr/bin/python

import argparse
from enum import unique
import json
import os

# starting with argparse to determine what the user wants to do

def get_args():
    
    parser = argparse.ArgumentParser(description="This is a script to get the list of deployed container images")
    parser.add_argument("-l", "--list", action="store_true", help="getting the list of deployed container imgages")
    parser.add_argument("-s", "--size", action="store_true", help="getting the size for the deployed container imgages")
    parser.add_argument("-u", "--ubi", action="store_true", help="getting the ubi comliance status for the deployed container imgages")
    parser.add_argument("-v", "--vuln", action="store_true", help="getting the cve finding summary for the deployed container imgages")
    parser.add_argument("-a", "--all", action="store_true", help="getting all reports... container image list && size && vuln && ubi")
    args = parser.parse_args()
    return args

# run functions based on user arguments

def parse_args(args):

    if args.all == True:
        print("### Generating the ALL reports ###")  
        generate_image_list()
        list_images()
        size_images()
        vuln_images()
        ubi_images()
    elif args.list == True:
        print("### Generating the LIST of deployed images ###")  
        generate_image_list()
        list_images()
    elif args.size == True:
        print("### Generating the SIZE report ###")
        generate_image_list()    
        size_images()
    elif args.vuln == True:
        print("### Generating the VULN findings count report ###")
        generate_image_list()    
        vuln_images()
    elif args.ubi == True:
        print("### Generating the UBI compliance report ###")
        generate_image_list()    
        ubi_images()    
    else:
        print("No option provided... What should we do?")
        print("Please use -h to find the available options") 
        exit(1)

def generate_image_list():

    print("Connecting to the k8s cluster to obtain the list of running images")
    print("This takes about 10s...")

    try:
        file = open("image_list.txt", "r+")
        file.truncate()    
    except Exception as e:
        file = open("image_list.txt", "w+")  

    import kubernetes as k8s
    try:
        k8s.config.load_kube_config()
        v1 = k8s.client.CoreV1Api()
        response_k8s = v1.list_namespaced_pod(namespace="eaa", watch=False)
        for pod in response_k8s.items:
            hs = open("image_list.txt","a")
            hs.write(f"{pod.spec.containers[0].image}" + "\n")
            hs.close() 
        with open('image_list.txt') as image_list:
            images = image_list.read().splitlines()
            images = list(dict.fromkeys(images))
            hs = open("image_list_uniq.txt","a")
            for image in images:
                hs.write(f"{image}" + "\n")
            hs.close()

        print("Removing non-mycom images from the list to be able to get the size of the images that are running on the k8s cluster")

        with open('image_list_uniq.txt') as image_list:
            images = image_list.read().splitlines()
            hs = open("image_list_uniq.txt","w")
            for image in images:
                if "docker.mycom-osi.com" in image:
                    hs.write(f"{image}" + "\n")
            hs.close()
    except k8s.client.exceptions.ApiException:
        print("You are not logged into the cluster. Please authenticate first before you use the util.")
        exit(1)
    except Exception as e:
        print(e)
        print("You probably dont have a valid .kube/config file on your system. Please check before you use the util")
        exit(1)

def list_images():
    
    print("##############################################")
    print("Done ! Result file: image_list_uniq.txt")
    print("##############################################")

def size_images():
    
    import boto3
    import pandas as pd
    
    print("##############################################")
    print("Let's get the image size report...")
    print("##############################################")

    region = 'eu-west-1'
    client = boto3.client('ecr')

    print("Getting the image sizes from ECR")
    print("Printing image sizes to stdout...")
    print("This takes about 60s...")

    with open('image_list_uniq.txt') as container_list:
        containers = container_list.read().splitlines()
        try: 
            with open("image_size.txt", "w") as hs:
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
                    hs.write(f"{repo}:{tag} size = {round(int(response['imageDetails'][0]['imageSizeInBytes'])/1e6)} MB"  + "\n")
                    print(f"{repo}:{tag} size = {round(int(response['imageDetails'][0]['imageSizeInBytes'])/1e6)} MB")
        except Exception as e:
            print("Oh no !")
            print(e)

    print("Sorting the file image_size.txt by size")

    df = pd.read_csv("image_size.txt", sep=" ", header=None)
    df = df.sort_values(by=3, ascending=False)
    df.to_csv("image_size_sorted.txt", sep=" ", index=False, header=False)

    print("##############################################")
    print("Done ! Result file: image_size_sorted.txt")
    print("##############################################")

def vuln_images():

    import boto3

    print("##############################################")
    print("Let's get the vulnerability count report...")
    print("##############################################") 
    
    region = 'eu-west-1'
    client = boto3.client('ecr')

    try:
        file = open("image_vulns.txt", "r+")
        file.truncate()    
    except Exception as e:
        file = open("image_vulns.txt", "w+")  

    print("Now getting the image vulns from ECR")
    print("Printing images with vulns to stdout...")
    print("This takes about 60s...")

    with open('image_list_uniq.txt', "r") as container_list:
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
            print("Done ! Result file: image_vulns.txt")
            print("##############################################")            
            print('Critical: ' + str(critical))
            print('High: ' + str(high))
            print('Medium: ' + str(medium))
            print('Low: ' + str(low))
            print("##############################################")  
        except Exception as e:
            print("Oh no !")
            print(e)
            
def ubi_images():
    
    import docker
    
    print("##############################################")
    print("Let's get the ubi compliance report...")
    print("##############################################")
    
    try:
        file = open("image_ubi.txt", "r+")
        file.truncate()    
    except Exception as e:
        file = open("image_ubi.txt", "w+")  

    print("Logging into the docker.mycom-osi.com container registry")

    client = docker.from_env()
    client.login(username="mycomosi", password="mo-eaa-ecr", registry="docker.mycom-osi.com")

    # the sha's of the lates ubi images
    ubi8_minimal_8_9_1029 = "sha256:8f42ad26ccdae7ec04dac9501e3c011a88c8663559699974ecf1697999914f0d"
    ubi8python39_1_155 = "sha256:d938174480191f5a4b9117a3a4ef6e22a48572994b50b71f863610a82b55d371"

    print("Getting the container image configs from the registry...")
    print("Printing non-compliant images to stdout...")
    print("This takes about 60s...")

    with open('image_list_uniq.txt') as container_list:
            containers = container_list.read().splitlines()
            try: 
                ubi_total_check = 0
                ubi_minimal_ok = 0
                ubi_python_ok = 0
                ubi_nok = 0
                for container in containers:
                    repo = container.split(":")[0]
                    tag = container.split(":")[-1]
                    response = json.loads(os.popen(f"crane config {container}").read())
                    diff_ids = json.dumps(response["rootfs"]["diff_ids"])
                    if ubi8_minimal_8_9_1029 in diff_ids:
                        hs = open("image_ubi.txt","a")
                        hs.write(f"{repo}:{tag} OK - contains the rootfs layer for ubi minimal"  + "\n")
                        hs.close() 
                        ubi_minimal_ok += 1
                        ubi_total_check += 1
                    elif ubi8python39_1_155 in diff_ids:
                        hs = open("image_ubi.txt","a")
                        hs.write(f"{repo}:{tag} OK - contains the rootfs layer for ubi python"  + "\n")
                        hs.close() 
                        ubi_python_ok += 1  
                        ubi_total_check += 1                      
                    else:
                        hs = open("image_ubi.txt","a")
                        hs.write(f"{repo}:{tag} NOK - Not UBI compliant"  + "\n")
                        hs.close() 
                        print(f"{repo}:{tag} NOT COMPLIANT")
                        ubi_nok += 1
                        ubi_total_check += 1
                print("##############################################")
                print("Done ! Result file: image_ubi.txt")
                print("##############################################")   
                print("##############################################")
                print('UBI minimal compliant: ' + str(ubi_minimal_ok))
                print('UBI python compliant: ' + str(ubi_python_ok))
                print('Not Compliant: ' + str(ubi_nok))
                print('Total checks: ' + str(ubi_total_check))                
                print("##############################################")
            except Exception as e:
                print("Oh no !")
                print(e)

def main():
    args = get_args()
    parse_args(args)
    
if __name__ == "__main__":
    main()