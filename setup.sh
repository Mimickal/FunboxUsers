echo "Installing all the requirements for FunboxUsers."

apt-get install build-essential libssl-dev python3 python3-dev libapache2-mod-wsgi python3-pip
pip3 install -r requirements.txt

if [ -z "$1" ] # Check if there actually was an arg
then
    echo "Add the command line option --test if you want to install the requirements for the tests."
    exit 0
else
    TEST="--test"
    if [ $1 = $TEST ] # Check if it matches the --test arg.
    then
        echo "Installing all the requirements for the tests."
        pip3 install -r test-requirements.txt
        echo "Creating test SSL keys"
        openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
    else
        echo "Add the command line option --test if you want to install the requirements for the tests."
    fi
fi
