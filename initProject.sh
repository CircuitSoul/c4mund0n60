#!/bin/bash

#VERIFY NUMBERS OF ARGUMENTS AND RUN IF THE USER INPUT 2 ARGUMENT
if [ $# -eq 2 ]; then
    TGT=$1
    DOMAINLIST=$2

    echo "[+] REMOVING OLD PROJECT [+]"
    rm -rf targets/$TGT
    echo "[+] CREATING NEW PROJECT [+]"
    mkdir targets/$TGT
    mkdir targets/$TGT/temp
    touch targets/$TGT/domains.txt

    if [ -f "$DOMAINLIST" ]; then
        if [ -r "$DOMAINLIST" ]; then
            echo "[+] CONFIGURATING YOUR DOMAINS"
            sleep 1
            cp $DOMAINLIST targets/$TGT/domains.txt
            exit 1
        else
            sleep 1
            echo "[+] The argument '$DOMAINLIST' is not a readable text file."
            exit 1
        fi
    fi

    echo "[+] FINISH [+]"

else
    if [ $# -eq 1 ]; then
        TGT=$1
        echo "[+] REMOVING OLD PROJECT [+]"
        sleep 1
        rm -rf targets/$TGT
        echo "[+] CREATING NEW PROJECT [+]"
        sleep 1
        mkdir targets/$TGT
        mkdir targets/$TGT/temp
        touch targets/$TGT/domains.txt

        sleep 1
        echo "[+] INSERT MANUALLY A TARGET DOMAINS IN THE TEXT FILE: $(pwd)/targets/$TGT/domains.txt"
        echo "[+] RUN echo 'example.com' >> $(pwd)/targets/$TGT/domains.txt"
        echo "[+] RUN python3 main.py $TGT"
        exit 1
    fi

    echo "Init a project at c4mund0n60 : "
    echo 
    echo "$0 <project-name>"
    echo "$0 <project-name> <aDomainList.txt>"
    exit 1
fi