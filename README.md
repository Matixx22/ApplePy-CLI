# ApplePy-CLI
Python packet sniffer and analyzer built with Click.

# Installation
These steps provides installation in virtual environment so create one after cloning the repository.

```{bash}
git clone https://github.com/Matixx22/ApplePy-CLI.git
cd ApplePy-CLI
pip install -r requirenments.txt
pip install --editable .
applepy --help
```

# Online server
In `applepy/server` there is a FastAPI application. For proper working you need to add networking capabilities to your Python interpreter first(insecure!). X.X should be replaced with your Python interpreter version e.g. for Python3.8 X.X will be 3.8.

```{bash}
sudo setcap cap_net_raw=eip /usr/bin/pythonX.X
cd applepy/server
uvicorn server:app --reload
```

After execution of these commands you should be able to go to `http://127.0.0.1:8000`, which is FastAPI server containing REST API endpoints.

If during testing after starting uvicorn server you get `[Errno 98] Address already in use` error, run `sudo lsof -t -i tcp:8000 | xargs kill -9`.

# Contribution 

Make branch from dev and do your coding, then create pull request.