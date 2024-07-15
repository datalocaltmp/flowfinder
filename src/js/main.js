/* eslint-disable */ 

/*
const urlParams = new URLSearchParams(window.location.search);
const gist = urlParams.get('gist');
*/

const { graphviz } = require('./d3-graphviz');

var svg = null;
var rawContents = null;

// Parses function data within a functionSignature extracted from a graph ndoe
function parseFunction(functionSignature, nodeKey){

    var className = null;
    var methodName = null;
    var functionArgs = null;
    var functionArgString = '';

    console.log('[*] parsing function: ' + functionSignature);

    // TODO: Fix java.lang support - currently taking a stacktrace adds to much overhead and causes crashes
    if(functionSignature.startsWith('java.lang')){
        return ['',''];
    }

    // magic regex (groups class, method, and parameters)
    const regexp = /(.*)\.([^.]*)\((.*)\)/gm;
    const matches = functionSignature.matchAll(regexp);
    for (const match of matches) {
        if(match.length == 4){
            className = match[1];
            methodName = match[2];
            
            // Hack that translates <init> to $init for frida
            if(methodName == '<init>'){
                methodName = '$init';
            }
            functionArgs = match[3];
        }else{
            console.log("[!] Error parsing function signature");
            return null;
        }
    }

    if(functionArgs.length > 0){
        // Creates string that looks like `'ClassX', 'ClassY', 'ClassZ'` and the associated params for frida i.e (X0, X1, X2)
        functionArgs = functionArgs.split(', ');
        for(var i = 0; i < functionArgs.length; i++){
            functionArgString = functionArgString.concat('X'+i+', ');
            if(functionArgs[i].includes('[]')){
                functionArgs[i] = '[L' + functionArgs[i].substring(0, functionArgs[i].length - 2)+';';
            }
        }
        if(functionArgString.length > 0)
            functionArgString = functionArgString.substring(0, functionArgString.length - 2);

        functionArgs = '\''+functionArgs.join('\',\'')+'\'';
    }else{
        // Empty argument strings and parameters
        functionArgs = '';
        functionArgString = '';
    }

    var cleanClassName = className.replaceAll('.','_');
    var cleanMethodName = cleanClassName+'_'+methodName;

    // Script which will find the class loader associated with the class
    var scriptClassLoader = `
    var ${cleanClassName}_factory = null;
    for (const classLoader in classLoaders) {
        try{
            classLoaders[classLoader].findClass('${className}');
            ${cleanClassName}_factory = Java.ClassFactory.get(classLoaders[classLoader]);
            break;
        }catch(e){
            continue;
        }
    }`;

    // Script that does the actual hooking of the class method
    var scriptFunctionHook = `
    if(${cleanClassName}_factory){
        var ${cleanClassName} = ${cleanClassName}_factory.use('${className}');

        var ${cleanMethodName} = ${cleanClassName}.${methodName};
        if(${cleanMethodName}){
            ${cleanMethodName}.overload(${functionArgs}).implementation = function(${functionArgString}){
                const breakpoint = /\\r?\\n/;
                var callingFunction = stackTrace().split(breakpoint)[2];
                var returnVal = null;

                if('${functionArgString}' != ''){
                    returnVal = ${cleanMethodName}.call(this, ${functionArgString});
                }else{
                    returnVal = ${cleanMethodName}.call(this);
                }

                //This call is not associated with our call graph
                if(!callingFunction.includes(entranceFunction)){
                    return returnVal;
                }

                send({'msg':'[*] Executing ${cleanMethodName} for node: ${nodeKey}', 'data':'${nodeKey}'});

                if(verboseOutput){
                    var funcargs = [${functionArgString}];
                    for(var k = 0; k < funcargs.length; k++){
                        send({'msg':'[*] ${cleanMethodName} argument ' + k + ': '+funcargs[k]});
                    }
                }

                if(verboseOutput){
                    send({'msg':'[*] ${cleanMethodName} return value : ' + returnVal});
                }

                return returnVal;
            }
        }else{
            send({'msg':'[!] Could not find method: ${cleanMethodName}'});
        }
    }else{
        send({'msg':'[!] Could not find class: ${className}'});
    }
`;
    return [scriptClassLoader, scriptFunctionHook];
}

// Extract data for frida script from entrance method and all nodes in graph
function extractGraphData(){
    
    // REGEX for graph title
    const funcNamePtrn = /([^.^(]*)\(/gm;
    const funcFullPtrn = /([^ ^()]*)\(/gm;

    // Object to be returned
    var data = {
        'entranceClass':null,
        'entranceFunction':null,
        'nodeHooks':[]
    };

    // Extract the entrance class and method name from the graphs title
    d3.selectAll('title')
    .nodes()
    .forEach(function (n) {
        var testString = n.innerHTML;
        if(testString.startsWith('CFG for')){
            //remove fixed CFG for prefix
            var functionString = testString.slice(7);
            var entranceClass = funcFullPtrn.exec(functionString).pop();
            var entranceFunction = funcNamePtrn.exec(functionString).pop();

            //TODO Clean up function class and method extraction
            data['entranceClass'] = entranceClass.slice(0, entranceClass.length - 1 - entranceFunction.length);
            data['entranceFunction'] = entranceFunction;
        }
    });

    // For each node in the graph; find all the calls to other methods and create a list of function hooks
    d3.selectAll('.node')
    .nodes()
    .forEach(function (n) {
        const regexp = / call: ([^:]*):/gm;

        // Ignore entrace function which is handled separately.
        if(n.__data__.key == 'MethodNode')
            return;

        // Read each line of a node looking for a regex match
        var nodeTextElements = n.textContent.split('\n');
        for(var i = 0; i < nodeTextElements.length; i++){
            if(nodeTextElements[i].includes(' call:')){
                const matches = nodeTextElements[i].matchAll(regexp);
                
                // for each call match - a.k.a a function call in a node
                for (const match of matches) {
                    
                    // create frida function hook for this call in the node (n)
                    var nodeID = n.__data__.key;
                    var functionHook = parseFunction(match[1], nodeID);
                    if(functionHook.length == 2){
                        
                        // functionHook[0] is the class loader search - only needs to happen once.
                        console.log('FACTORY: '+functionHook[1]);
                        console.log('FUNCTION HOOK: '+functionHook[0]);
                        if(data['nodeHooks'].indexOf(functionHook[0]) == -1){
                            data['nodeHooks'].push(functionHook[0]);
                        }

                        // functionHook[1] is the actual method hook - need at least one per node key
                        if(data['nodeHooks'].indexOf(functionHook[1]) == -1){
                            data['nodeHooks'].push(functionHook[1]);
                        }
                    }
                }
            }
        }
    });

    return data;
}

/*
    generateFridaScript generates the graph data and then injects it into a template to download
 */
function generateFridaScript(){

    // Grab highlight color from the DOM
    var highlightColor = document.getElementById('highlight').value;

    // Grab and set verboseOutput from the DOM - used to set verbose logging in frida script
    var verboseOutput = false;
    if(document.getElementById('verbose').checked){
        verboseOutput = true;
    }

    // As long as a svg graph is available and the rawContents are loaded
    if(svg && rawContents != null){

        // Extract the graph data - which is the entrance class/method and all the internal node methods
        var data = extractGraphData();
        
        // Combile all the node hooks into one large script
        var nodeScript = '';
        if(data.nodeHooks.length > 0){
            nodeScript = data.nodeHooks.join('\n');
        }

        var javascriptContent = `
/*
* happy hunting!
*/
"use strict";

send({'msg':'[+] Loaded script into process'})

const verboseOutput = ${verboseOutput};

// Generated frida script below
Java.perform(() => {
    //Grab all class loaders - necessary to use all classes within program
    var classLoaders = Java.enumerateClassLoadersSync();

    // Classes for generating a stacktrace
    var Exception = Java.use('java.lang.Exception');
    var Log = Java.use('android.util.Log');
    var entranceStack = null;

    // Entrance class and function
    var entranceFunction = '${data['entranceClass']}.${data['entranceFunction'].replace('\\\&gt;', '>').replace('\\\&lt;', '<')}';

    ${nodeScript}

    function stackTrace() {
        return Log.getStackTraceString(Exception.$new());
    }
});`;
        
        var scriptContent = `
#!/usr/bin/env python
from __future__ import print_function

import argparse
import re
import os
import signal
import sys

import frida

"""
Frida Java coverage tool that outputs in .dot format - based on gaasedelen/lighthouse/master/coverage/frida/frida-drcov.py

Frida script is responsible for:
- Instrumenting Java calls
- Signaling to the Python side which nodes have been executed

Python side is responsible for:
- Attaching and detaching from the target process
- Receiving node execution signals and updating associated .dot file
- Writing the output file upon sigint
"""

graphData = r"""
${rawContents}
"""

js = r"""
${javascriptContent}
"""

# File to capture the output of node execution
outfile = 'flow-cov.dot'
bbs = set()

def recurse_nodes(node):
    global graphData

    bbs.add(node)

    # Add all forward nodes if there is only one
    forwardCount = graphData.count(node + ' -> ')
    if(forwardCount == 1):
        forwardPattern = node + r" -> ([a-zA-Z_0-9]*)[;[]"
        forwardNode = re.search(forwardPattern, graphData).group(1)
        if(not forwardNode in bbs):
            if(graphData.count(node + ' -> ' + forwardNode+'[') > 0):
                graphData = graphData.replace(node + ' -> ' + forwardNode+'[', node + ' -> ' + forwardNode + '[style=bold, color="red", ')
            else:
                graphData = graphData.replace(node + ' -> ' + forwardNode, node + ' -> ' + forwardNode + '[style=bold, color="red"]')
            print('[*] Implicit execution for node: ' + forwardNode)
            recurse_nodes(forwardNode)
    
    # TODO: This looks crappy but its just to account for node followed by [ or ;
    backwardCount = graphData.count(' -> ' + node + ';') + graphData.count(' -> ' + node + '[')
    if(backwardCount == 1):
        backwardPattern = r"([a-zA-Z_0-9]*) -> " + node + r"[;[]"
        backwardNode = re.search(backwardPattern, graphData).group(1)
        if(not backwardNode in bbs):
            if(graphData.count(backwardNode + ' -> ' + node+'[') > 0):
                graphData = graphData.replace(backwardNode + ' -> ' + node+'[', backwardNode + ' -> ' + node + '[style=bold, color="red", ')
            else:
                graphData = graphData.replace(backwardNode + ' -> ' + node, backwardNode + ' -> ' + node + '[style=bold, color="red"]')
            print('[*] Implicit execution for node: ' + backwardNode)
            recurse_nodes(backwardNode)

def on_message(msg, data):
    if 'payload' in msg and 'msg' in msg['payload']:
        print(msg['payload']['msg'])
        if('data' in msg['payload']):
            recurse_nodes(msg['payload']['data'])

def sigint(signo, frame):
    print('[!] SIGINT, saving %d blocks to \\\'%s\\\'' % (len(bbs), outfile))

    save_coverage()

    print('[!] Done')

    os._exit(1)

def save_coverage():
    global graphData

    with open(outfile, 'wb') as h:
        if(len(bbs) > 0):
            originalStr = 'MethodNode['
            replaceStr = 'MethodNode[style="filled", color="${highlightColor}", '
            graphData = graphData.replace(originalStr, replaceStr)
            recurse_nodes('MethodNode')

        for bb in bbs:
            originalStr = bb + ' ['
            replaceStr = bb + ' [style="filled", color="${highlightColor}", '
            graphData = graphData.replace(originalStr, replaceStr)

        h.write(graphData.encode())

def main():
    global outfile

    parser = argparse.ArgumentParser()
    parser.add_argument('target',
            help='target process name or pid',
            default='-1')
    parser.add_argument('-o', '--outfile',
            help='coverage file',
            default='flow-cov.dot')
    parser.add_argument('-D', '--device',
            help='select a device by id [local]',
            default='local')

    args = parser.parse_args()

    outfile = args.outfile

    device = frida.get_device(args.device)

    target = -1
    for p in device.enumerate_processes():
        if args.target in [str(p.pid), p.name]:
            if target == -1:
                target = p.pid
            else:
                print('[-] Warning: multiple processes on device match '
                        '\\\'%s\\\', using pid: %d' % (args.target, target))

    if target == -1:
        print('[-] Error: could not find process matching '
                '\\\'%s\\\' on device \\\'%s\\\'' % (args.target, device.id))
        sys.exit(1)

    signal.signal(signal.SIGINT, sigint)

    print('[*] Attaching to pid \\\'%d\\\' on device \\\'%s\\\'...' %
            (target, device.id))

    session = device.attach(target)
    print('[+] Attached. Loading script...')

    script = session.create_script(js)
    script.on('message', on_message)
    script.load()

    print('[*] Now collecting info, control-C or control-D to terminate....')

    sys.stdin.read()

    print('[*] Detaching, this might take a second...')
    session.detach()

    print('[+] Detached. Got %d basic blocks.' % len(bbs))
    print('[*] Formatting coverage and saving...')

    save_coverage()

    print('[!] Done')

    sys.exit(0)

if __name__ == '__main__':
    main()`;

        const link = document.createElement('a');
        const file = new Blob([scriptContent], { type: 'text/plain' });
        link.href = URL.createObjectURL(file);
        link.download = 'flow_script.py';
        console.log(scriptContent);
        link.click();
        URL.revokeObjectURL(link.href);
    }else{
        alert('Load a .dot file first.');
    }
}

// Associate function with button in dom
window.generateFridaScript = generateFridaScript;

// Read in .dot file
function readDotFile(e) {
    var file = e.target.files[0];
    if (!file) {
        return;
    }
    var reader = new FileReader();
    reader.onload = function(e) {
        var contents = e.target.result;
        // Grab file and render graph
        renderGraph(contents);
    };
    reader.readAsText(file);
}

// When new file input is selected run readDotFile
document.getElementById('file-input').addEventListener('change', readDotFile, false);

// Attributer to style graph
function attributer(d){

    // Set paths to white
    if(d.tag == 'path' && d.attributes.stroke == 'black'){
        d.attributes.stroke = '#fff';
    }

    // Set arrows to white
    if(d.tag == 'polygon' && d.key == 'path-1' && d.attributes.stroke == 'black'){
        d.attributes.stroke = '#fff';
        d.attributes.fill = '#fff';
    }

    // Set node fill color to #333
    if(d.tag == 'polygon' && d.key != 'path-1' && d.attributes.fill == 'none'){
        d.attributes.fill = '#333';
    }
    
    // Set all lines to black
    if(d.tag == 'polygon' && d.key == 'path-0' && d.parent.parent.tag == 'svg'){
        d.attributes.stroke = '#000';
        d.attributes.fill = '#000';
    }

    // Set all text to white
    if(d.tag == 'text'){
        d.attributes.fill = '#ffffff';
    }

    // Ensure graph is centered and scaled properly
    // Attribution: https://stackoverflow.com/questions/67626414/scale-and-center-d3-graphviz-graph
    if (d.tag == 'svg') {
        var selection = d3.select(this);
        var scale = 0.8;

        d.attributes = {
            ...d.attributes,
            width: '50%',
            height: '50%',
        };
        // svg is constructed by hpcc-js/wasm, which uses pt instead of px, so need to convert
        const px2pt = 1 / 4;

        // get graph dimensions in px. These can be grabbed from the viewBox of the svg
        // that hpcc-js/wasm generates
        const graphWidth = d.attributes.viewBox.split(' ')[2] / px2pt;
        const graphHeight = d.attributes.viewBox.split(' ')[3] / px2pt;

        // new viewBox width and height
        const w = graphWidth / scale;
        const h = graphHeight / scale;

        // new viewBox origin to keep the graph centered
        const x = -(w - graphWidth) / 2;
        const y = -(h - graphHeight) / 2;

        const viewBox = `${x * px2pt} ${y * px2pt} ${w * px2pt} ${h * px2pt}`;
        selection.attr('viewBox', viewBox);
        d.attributes.viewBox = viewBox;
    }
}

// Render the graph - occurs on file selection.
function renderGraph(graphText){

    //TODO: Find a better way to make the splines orthogonal.
    //      Ensures the splines are orthogonal - a.k.a lines are at right angles
    if(!graphText.includes('splines')){
        var graphTextArray = graphText.split('\n');
        graphTextArray.splice(1,0, 'splines=ortho;');
        graphText = graphTextArray.join('\n');
    }
    
    // Save the graphText off as raw contents somewhere
    rawContents = graphText;

    // Delete any old graph to make way for new graph
    const element = document.getElementById('graph');
    element.remove();

    // Create new graph under the graph-holder element
    const graphNode = document.createElement('div');
    graphNode.setAttribute('id', 'graph');
    graphNode.setAttribute('style', 'text-align: center; height: 100%;');
    document.getElementById('graph-holder').appendChild(graphNode);

    // Create and render graph - note the attributer
    d3.select('#graph').graphviz()
        .fit(true)
        .attributer(attributer)
        .engine('dot')
        .tweenPaths(true)
        .dot(graphText)
        .render();
    
    // Used to confirm that a .dot file has been loaded
    svg = true;
}
