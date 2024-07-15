![](./dist/imgs/LOGO.png)

flowfinder is a simple webapp that takes .dot files representing Android Methods produced by jadx, generates corresponding frida-scripts, and using frida annotates the graph with metadata on method execution.

## Building & Running

install with `npm install`

run with `npm run watch`

EZ-PZ!

## TODO

 - [X] Generate frida snippet correspdoning to .dot files.
 - [X] Support ingesting output of frida snippet.
    - Makes sense to have frida annotate original .dot file with metadata so it can be ingested via initial input field
 - [X] Support annotating with Java types.
 - [X] Support annotating with toString(); results per argument
 - [X] Support annotating with toString(); results per return

