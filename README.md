# Toguro FE

This project contains the frontend for the main Toguro platform using [Matrix Js SDK](https://github.com/matrix-org/matrix-js-sdk)

It includes the built `.es.js` of [Mx-Login-App](https://github.com/hmendes00/login-mx-app) for reference.

You should be able to easily integrate any app created using [toguro-cli](https://github.com/hmendes00/toguro-cli). Feel free to create and share some app as well :)

Toguro-cli + Apps + Toguro FE (this project) simplified architecture
![Architecture](https://i.ibb.co/BBbZPg4/Untitled-Artwork-5.png)

## Requirements

- Node 16
- NVM

> ** Note: **
> NVM might not exist for Windows so feel free to use any Node.JS Version Manager as long as you are using the Node 16 version

if you are using node globally and you don't have a Node.JS Version Manager, make sure you install one to avoid upgrading or downgrading your global node version.

To install NVM

```bash
curl -o- https://raw.githubusercontent.com/creationix/nvm/v0.33.1/install.sh | NVM_DIR=/usr/local/nvm bash
```

## How to install

First make sure you are inside of _SRC_ folder (and not STACK folder)

Then run the following command to enforce the correct NodeJS version for the project:

```bash
nvm use
```

Then install the dependencies:

```bash
npm install
```

You might want to change the `VITE_MATRIX_URL` in the `.env` file to point to your own homeserver. o/

## How to run

First make sure you are inside of _SRC_ folder (and not STACK folder)

Then run the following command

```bash
npm run dev
```

## How to setup my custom app

You will see a file called fake-api.json.
You should essentially change the values according to how you named your custom app and what was the generated appid.

E.G:

```
"appName": "toguro-test-app",
"appUrl": "http://localhost:3000/src/main.ts",
"developerEmail": "hmendes00@gmail.com",
"hasSupport": true,
"appVersion": "1",
"target": "menu",
"appType": "page",
"label": "My Test Label",
"appId": "d95b4121-4222-4752-8674-b832k4cef93e"
```

The app will be automatically injected and rendered inside of a `custom-page-app` route.
It should also generate a menu with the label "My Test Label" (As defined in the json).

The idea is that your app will, at some point, come from a real api call.

The way it will "end up" in your db is by publishing the api through the `toguro-cli`.
This will add the app to the app marketplace of toguro's ecossystem.

Of course you can create your own way of publishing this and dealing with this whole thing.
My idea here is to have a base website where people can create any types of websites using latest tech and using the app marketplace to build those pages block.

## How to test

> http://localhost:8080/

## Global Event Listeners

Should be used by login apps so you can know when a user is logged in or not
`toguro-events:login-updated`

## How to deploy

TBD
