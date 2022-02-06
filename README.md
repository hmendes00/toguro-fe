# Toguro FE

This project contains the frontend for the main Toguro platform

## Requirements

* Node 16
* NVM

>** Note: ** 
NVM might not exist for Windows so feel free to use any Node.JS Version Manager as long as you are using the Node 16 version


if you are using node globally and you don't have a Node.JS Version Manager, make sure you install one to avoid upgrading or downgrading your global node version.

To install NVM
```bash
curl -o- https://raw.githubusercontent.com/creationix/nvm/v0.33.1/install.sh | NVM_DIR=/usr/local/nvm bash
```



## How to install

First make sure you are inside of *SRC* folder (and not STACK folder)

Then run the following command to enforce the correct NodeJS version for the project:
```bash
nvm use
```
Then install the dependencies:
```bash
npm install
```

## How to run

First make sure you are inside of *SRC* folder (and not STACK folder)

Then run the following command
```bash
npm run dev
```

## How to setup my custom app

You will see a file called fake-api.json.
You should essentially change the values according to how you named your custom app and what was the generated appid.

E.G:
```
"appName": "toguro-assessment-app",
"appUrl": "http://localhost:3000/src/main.ts",
"developerEmail": "hmendes00@gmail.com",
"hasSupport": true,
"appVersion": "1",
"target": "menu",
"appType": "page",
"label": "Assessments",
"appId": "d95b4121-4222-4752-8674-b832k4cef93e"
```

The app will be automatically injected and rendered inside of a `custom-page-app` route.
It should also generate a menu with the label "Assessments" (As defined in the json).

The idea is that your app will, at some point, come from a real api call.

The way it will "end up" in your db is by publishing the api through the `toguro-cli`.
This will add the app to the app marketplace of toguro's ecossystem.

Of course you can create your own way of publishing this and dealing with this whole thing.
My idea here is to have a base website where people can create any types of websites using latest tech and using the app marketplace to build those pages block.

## How to test

> http://localhost:8080/

## How to deploy

TBD
