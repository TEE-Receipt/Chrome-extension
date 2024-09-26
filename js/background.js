/* Copyright (c) 2018 Aalto University
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//import aesjs from './deps/aesjs/index.js';

var disableScripts;
var SGXQuote;
var rng = new SecureRandom();
var key_pair = gen_keypair();
var signingkey;
var encrypted_signingkey;
var shared_keysetted=false;
var currenttabid=0;
var dh_key_str;
var gb_str;

let user_signed_in = false;

let use_drive=false;

//save a received evidence locally.

function saveLocal(filename,fileContent)
{
  var vLink = document.createElement('a'),
  vBlob = new Blob([fileContent], {type: "octet/stream"}),
  vName = filename+'.txt',
  vUrl = window.URL.createObjectURL(vBlob);
  vLink.setAttribute('href', vUrl);
  vLink.setAttribute('download', vName );
  vLink.click();
}
function uploadFileToDrive(fileName,fileContent,token)
{
  var metadata = {
      name: fileName+'.json',
      mimeType: 'application/json',
      parents:'TransactionsEvidence'
  };

  console.log(fileContent);
  console.log(token);
  var file = new Blob([JSON.stringify(fileContent)], {type: 'application/json'});
  var form = new FormData();
  form.append('metadata', new Blob([JSON.stringify(metadata)], {type: 'application/json'}));
  form.append('file', file);

  var xhr = new XMLHttpRequest();
  xhr.open('POST', 'https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart');
  xhr.setRequestHeader('Authorization', 'Bearer ' + token);
  xhr.responseType = 'json';
  xhr.onload = () => {
      var fileId = xhr.response.id;
      console.log("uploaded file with ID"+fileId);
      /* Do something with xhr.response */
  };
  xhr.send(form);
}

function is_user_signed_in() {
    return user_signed_in;
}

// function _arrayBufferToBase64( buffer ) {
//     var binary = '';
//     var bytes = new Uint8Array( buffer );
//     var len = bytes.byteLength;
//     for (var i = 0; i < len; i++) {
//         binary += String.fromCharCode( bytes[ i ] );
//     }
//     return window.btoa( binary );
// }
// function str2ab(str) {
//   const buf = new ArrayBuffer(str.length);
//   const bufView = new Uint8Array(buf);
//   for (let i = 0, strLen = str.length; i < strLen; i++) {
//     bufView[i] = str.charCodeAt(i);
//   }
//   return buf;
// }
// function ba2str( ba ) {
//     var res = "";
//     for( var i=0, len = ba.length; i < len; i++ ) {
//         res += ba[i].toString();
//     }
//
//     return res;
// }
function hex2ba(str)
{
  var bytes = new Uint8Array(Math.ceil(str.length / 2));
  for (var i = 0; i < bytes.length; i++) bytes[i] = parseInt(str.substr(i * 2, 2), 16);
  return bytes;
}
// function concatinatebuffers(buffer1, buffer2) {
//   var tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
//   tmp.set(buffer1, 0);
//   tmp.set(buffer2, buffer1.byteLength);
//   return tmp.buffer;
// };
// function ab2b64(arrayBuffer) {
//     return window.btoa(String.fromCharCode.apply(null, new Uint8Array(arrayBuffer)));
// }

// There is b64toBA from jsbn that does the same
function b64quote2ba( quote ) {
    var res = new Uint8Array(1116);
    bin_quote = atob(quote);
    for( var i=0, strLen = bin_quote.length; i < strLen; i++ ) res[i] = bin_quote.charCodeAt(i);

    return res;
}

// Helper

function gen_keypair() {
    var curve = getSECCurveByName( "secp256r1" );

    var n = curve.getN();
    var n1 = n.subtract(BigInteger.ONE);

    // Generate a random number in F(n-1) (private key)
    var r = new BigInteger(n.bitLength(), rng);
    r = r.mod(n1).add(BigInteger.ONE);
    // console.log("Private key b");
    // console.log(r.toString(16));

    // Compute g^r - public key
    var G = curve.getG();
    var P = G.multiply(r);

    // P is a point on the curve. Can do P.getX().toBigInteger().toString()
    return {"ecprv": r, "ecpub": P};
}

function compute_shared_key( ecpub, ecprv ) {
    var curve = getSECCurveByName( "secp256r1" );

    return ecpub.multiply(ecprv);
}

function get_ga_from_quote( quote ) {
    var curve = getSECCurveByName( "secp256r1" ).curve;

    var quote_ba = b64quote2ba( quote );
    var dh_ga = quote_ba.slice(48, 432).slice(320, 384);
    var dh_ga_x = dh_ga.slice(0, 32);
    var dh_ga_y = dh_ga.slice(32, 64);
    //dh_ga_x.reverse();
    //dh_ga_y.reverse();
    console.log("Quote_ba"+quote_ba);
    console.log("dh_ga:"+dh_ga);
    console.log("dh_ga_x:"+dh_ga_x);
    console.log("dh_ga_y:"+dh_ga_y);
    // Now dh_ga_x and dh_ga_y are coordinates of the point on the curve
    // Create that point
    var ga_p = new ECPointFp(curve,
            curve.fromBigInteger(parseBigInt(BAtohex(dh_ga_x),16)),
            curve.fromBigInteger(parseBigInt(BAtohex(dh_ga_y),16)));

    return ga_p;
}
// For measurments purposes we defined these Functions
// function derive_key_test( dh_key ) {
//     var sha256 = new sjcl.hash.sha256();
//     var x_hex = dh_key.slice(0, 64);
//
//     for(var i = 0; i < 32; i++) {
//       sha256.update( x_hex[62-2*i] );
//       sha256.update( x_hex[63-2*i] );
//     }
//
//     var key = sha256.finalize();
//     //var key = sjcl.hash.sha256.hash( hexstr2ba(dh_key) );
//     console.log("In derive_key dh_key(hex): " + dh_key);
//     console.log("In derive_key sha256(dh_key.x_hex_little): " + key);
//     var res = new Uint8Array(32);
//     for(var i = 0; i < 8; i++) {
//         var uk = key[i] >>> 0;
//         res[4*i + 0] = uk >> 24;
//         res[4*i + 1] = uk >> 16;
//         res[4*i + 2] = uk >> 8;
//         res[4*i + 3] = uk;
//     }
//     return res.slice(0,16);
//     //return hex2ba(dh_key).slice(0,16);
// }

///////
var onIASResponse = function( xhrState, xhrStatus, xhrResponse ) {
    if( xhrState == XMLHttpRequest.DONE && xhrStatus == 200 ) {
        console.log( "SafeKeeper: the IAS response is 200 OK" );
        // console.log( xhrResponse );
        // make sure xhrResponse is isvQuoteOK

        var ga_bn = get_ga_from_quote( SGXQuote );
        // console.log( "The G*a from the quote is: " );
        // console.log(ga_bn.getX().x.toString(16));
        // console.log(ga_bn.getY().x.toString(16));

      //var key_pair = gen_keypair();
        var dh_key = compute_shared_key( ga_bn, key_pair.ecprv );

        var dh_key_str = dh_key.getX().x.toString(16) + dh_key.getY().x.toString(16);
        var gb_str = key_pair.ecpub.getX().x.toString(16) + key_pair.ecpub.getY().x.toString(16);
        if(dh_key_str.length%2)
        {
          dh_key_str='0'+dh_key_str;
        }
        if(gb_str.length%2)
        {
          gb_str='0'+gb_str;
        }
        // console.log("dh_key_str"+dh_key_str);
        // console.log("dh_key:"+dh_key);
        // console.log("g*b: x "+key_pair.ecpub.getX().x);
        // console.log("g*b: y "+key_pair.ecpub.getY().x);
        return {'dh_key_str':dh_key_str,'gb_str':gb_str};
    }
    else {
      console.log("Something wrong");
    }
}

var onIncomingHeaders = function( details ) {
    // console.log( "SafeKeeper: onHeaders" );
    if( details.responseHeaders === undefined ) {
        console.warn( "TEEReceipt: no headers in the response" );
        console.log(details);
        return;
    }
    // console.log( "TEEReceipt: headers are.", details.responseHeaders );
    details.responseHeaders.forEach( function(v,i,a) {
      if(v.name == "x-safekeeper-sgx-quote" || v.name == "X-Safekeeper-Sgx-Quote") {
        SGXQuote = v.value;
        // console.log( "TEEReceipt: verifying quote with IAS" );
        var req_body = {"isvEnclaveQuote": v.value};
        var url = "https://api.trustedservices.intel.com/sgx/dev/attestation/v4/report";
        var xhr = new XMLHttpRequest();
        xhr.open( "POST", url, false );
        xhr.setRequestHeader("Ocp-Apim-Subscription-Key","1908e189392641368b3a2fa5bc1db9d6");//linkable
        xhr.setRequestHeader("Content-Type","Application/json");
        var starttime,endtime;
        starttime=new Date();
        xhr.onreadystatechange = function() {
          endtime=new Date();
          // console.log("IAS ELAPSED TIME"+(endtime-starttime));
          let ret=onIASResponse( xhr.readyState, xhr.status, xhr.responseText );
          if(ret!==undefined)
          {
            dh_key_str=ret.dh_key_str;
            gb_str=ret.gb_str;
          }
        }
        xhr.send(JSON.stringify(req_body));

      }
    else if(v.name=="x-teereceipt-sgx-skey")
      {
        // console.log("skey"+v.value);
        encrypted_signingkey=v.value;
      }
    else if(v.name=="x-teereceipt-transaction-log")
    {
      // console.log("Received Evidence:"+v.value);

        chrome.tabs.query({
            active: true,
            lastFocusedWindow: true
        }, function(tabs) {
            // and use that tab to fill in out title and url
            var tab = tabs[0];
            // console.log(tab.url);
            // alert(tab.url);
            var currentDateTime=new Date();
            var currentDateTimeString=currentDateTime.getFullYear()+"_"+currentDateTime.getMonth()+"_"+currentDateTime.getDate()+"_"+currentDateTime.getHours()+"_"+currentDateTime.getMinutes()+"_"+currentDateTime.getSeconds();
            var fileName=tab.url+""+currentDateTimeString;
            if(use_drive)
            {
              chrome.identity.getAuthToken({ interactive: true }, function (token) {
                 // console.log("Token:"+token);

                 uploadFileToDrive(fileName,v.value,token);

             });
           }
           else {
               saveLocal(fileName,v.value);
           }
        });


    }
    });
    if(dh_key_str!==undefined)
    {
      if(encrypted_signingkey!==undefined)// to verify that the quote verification step is done
      {
        // console.log("skey"+encrypted_signingkey);
          if(currenttabid !== undefined){
                //console.log("Current tap Id"+tabs[0].id);
                chrome.tabs.sendMessage(currenttabid,
                        {shared_key: dh_key_str, gb: gb_str,encrypted_signingkey:encrypted_signingkey}, function (response) {
                            if(response.signingkey!==undefined)
                            {
                              console.log(response.signingkey);
                              signingkey=response.signingkey;
                            }
                        });
            }
            else {
              console.log("cannot reach the tab");
            }
      }
      else {
          if(currenttabid !== undefined){
                  //console.log("Current tap Id"+tabs[0].id);
                  chrome.tabs.sendMessage(currenttabid,
                          {shared_key: dh_key_str, gb: gb_str}, function (response) {
                            console.log(response);
                          });
              }
              else {
                console.log("cannot reach the tab");
              }
      }
    }

}

chrome.webRequest.onHeadersReceived.addListener(
    onIncomingHeaders,
    {urls: ["<all_urls>"]},
    ["responseHeaders", "blocking"]
);

// When we switch from one active tab to another,
// the content script is not injected again.
// So addListner to "activated" event.
chrome.tabs.onActivated.addListener(function(info) {
    chrome.tabs.query({active: true, currentWindow: true, status: "complete"}, function (tabs) {
        if(tabs[0] !== undefined){
            chrome.tabs.sendMessage(tabs[0].id, {check: "SGXEnabled?"}, function (response) {
                if( response === undefined || response.answer === undefined ) {
                   console.log("page cannot be loaded");
                    return;
                }
                if(response.answer === "SGXEnabled&ProtectedMode") {
                    chrome.browserAction.setIcon({path: 'images/lock_small.png', tabId: tabs[0].id});
                    chrome.browserAction.setPopup({ popup: 'html/supported.html'});
                }
                else if(response.answer === "SGXNotEnabled") {
                    chrome.browserAction.setIcon({path: 'images/cross_small.png', tabId: tabs[0].id});
                    chrome.browserAction.setPopup({ popup: 'html/not_supported.html'});
                }
                else if(response.answer === "SGXEnabled&NotProtectedMode"){
                    chrome.browserAction.setIcon({path: 'images/grey_lock_tiny.png', tabId: tabs[0].id});
                    chrome.browserAction.setPopup({ popup: 'html/supported.html'});
                }
            });
        }
    });
});


chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
    //one side communication, the content script just sends a message about sgx in the beginning
    console.log("TEEReceipt: background.onMessage: type " + request.type +
                ", clicked " + request.clicked);

    if(request.type === "SGXEnabled"){
        currenttabid=sender.tab.id;
        console.log("TEEReceipt: sender tab id " + sender.tab.id);
        chrome.browserAction.setIcon({path: 'images/grey_lock_tiny.png', tabId: sender.tab.id});
        chrome.browserAction.setPopup({ popup: 'html/supported.html'});
        //this message is here to dynamically change the state of the tab
    } else if (request.type === "SGXNotEnabled"){
        chrome.browserAction.setIcon({path: 'images/cross_small.png', tabId: sender.tab.id});
        chrome.browserAction.setPopup({ popup: 'html/not_supported.html'});
    }
    else if (request.type === "ProtectedModeOn"){
        console.log("TEEReceipt: turning ProtectedMode on");
        chrome.tabs.query({active: true, currentWindow: true, status: "complete"}, function (tabs) {
            chrome.browserAction.setIcon({path: 'images/lock_small.png', tabId: tabs[0].id});
        });
    }
    else if (request.type === "ProtectedModeOff"){
        chrome.tabs.query({active: true, currentWindow: true, status: "complete"}, function (tabs) {
            chrome.browserAction.setIcon({path: 'images/grey_lock_tiny.png', tabId: tabs[0].id});
        });
    }
    else if (request.clicked){
        chrome.tabs.query({active: true, currentWindow: true, status: "complete"}, function (tabs) {
            chrome.tabs.sendMessage(tabs[0].id, {inject: true}, function (response) {});
        });
    }
    else if(request.message === 'login')
    {
       chrome.identity.getAuthToken({ interactive: true }, function (token) {
          // console.log("Token:"+token);
          sendResponse('success');
      });

    }
    else if(request.message === 'logout') {
        user_signed_in = false;
        sendResponse('success');
        // chrome.browserAction.setPopup({ popup: './html/supported.html' }, () => {
        //     sendResponse('success');
        // });

        return true;
    } else if (request.message === 'isUserSignedIn') {
        sendResponse(is_user_signed_in());
    }
    else if(request.usedrive!== undefined)
    {
      use_drive=request.usedrive;
      console.log("use_drive:"+use_drive);
    }
});

chrome.storage.onChanged.addListener(function(changes, namespace) {
    for (key in changes) {
        var storageChange = changes[key];
        disableScripts = storageChange.newValue;
        console.log('TEEReceipt: storage key "%s" in namespace "%s" changed. ' +
                    'Old value was "%s", new value is "%s".',
                    key, namespace,
                    storageChange.oldValue, storageChange.newValue);
    }
});
