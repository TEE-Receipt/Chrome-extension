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

var click = false;

// If testing is needed, set to "password", for example
// and include an input field named "password" into HTML
var sgx_input = '';

// Is SGXEnabled meta field provided
var sgx_enabled = false;

var protected_mode = false;
var meta_inserted = false;
var disableScripts = false;

var dh_key = '';
var gb_key = '';
var signingkey;

chrome.storage.local.get({userUrls: []}, function(items) {
    for (var i=0; i < items.userUrls.length; i++) {
        if(items.userUrls[i].URL === location.href){
            disableScripts = true;
            console.log("disableScripts"+disableScripts);
            console.log("TEEReceipt: Content script: YES");
            break;
        }
    }
});

function nodeInserted(event) {
    if(meta_inserted == false && disableScripts){
        meta_inserted = true;
        var element = document.createElement('meta');
        element.setAttribute('http-equiv', 'Content-Security-Policy');
        element.content = "script-src none";
        document.getElementsByTagName('head')[0].appendChild(element);
    }
};

document.addEventListener('DOMNodeInserted', nodeInserted);

window.addEventListener("resize", function() {
  if(protected_mode == true){
    var $clones = $('[name="clone"]');
    var $allPasswordBoxes = $("input[type='" + sgx_input + "']");
    for(i = 0; i < $clones.length; i++){
	  $($clones[i]).tooltip("close");
	  $($clones[i]).css({
		'top': $($allPasswordBoxes[i]).offset().top,
		'left': $($allPasswordBoxes[i]).offset().left,
		'width': $($allPasswordBoxes[i]).outerWidth(),
		'height': $($allPasswordBoxes[i]).outerHeight()
		});
    // Set collision to none to avoid changing the side of input field on resize
	$($clones[i]).tooltip({ position: {collision: "none", my: "left+10 center", at: "right center", using: function( position, feedback ) {
          $( this ).css( position );
          $( "<div>" )
            .addClass( feedback.vertical )
            .addClass( feedback.horizontal )
            .appendTo( this );
        }}, content: "This input field will be encrypted before leaving your computer", offset: [-2, 10], opacity: 0.8});
	   $($clones[i]).tooltip("open");
    }
  }
}, false);

// Derive the key from the shared DH key
function derive_key( dh_key ) {
    var sha256 = new sjcl.hash.sha256();
    var x_hex = dh_key.slice(0, 64);

    for(var i = 0; i < 32; i++) {
      sha256.update( x_hex[62-2*i] );
      sha256.update( x_hex[63-2*i] );
    }

    var key = sha256.finalize();
    //var key = sjcl.hash.sha256.hash( hexstr2ba(dh_key) );
    console.log("In derive_key dh_key(hex): " + dh_key);
    console.log("In derive_key sha256(dh_key.x_hex_little): " + key);
    var res = new Uint8Array(32);
    for(var i = 0; i < 8; i++) {
        var uk = key[i] >>> 0;
        res[4*i + 0] = uk >> 24;
        res[4*i + 1] = uk >> 16;
        res[4*i + 2] = uk >> 8;
        res[4*i + 3] = uk;
    }
    return res.slice(0,16);
    //return hex2ba(dh_key).slice(0,16);
}

function hex2ba(str)
{
  var bytes = new Uint8Array(Math.ceil(str.length / 2));
  for (var i = 0; i < bytes.length; i++) bytes[i] = parseInt(str.substr(i * 2, 2), 16);
  return bytes;
}
var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
function encode(arraybuffer) {
  var bytes = new Uint8Array(arraybuffer),
  i, len = bytes.length, base64 = "";

  for (i = 0; i < len; i+=3) {
      base64 += chars[bytes[i] >> 2];
      base64 += chars[((bytes[i] & 3) << 4) | (bytes[i + 1] >> 4)];
      base64 += chars[((bytes[i + 1] & 15) << 2) | (bytes[i + 2] >> 6)];
      base64 += chars[bytes[i + 2] & 63];
  }

  if ((len % 3) === 2) {
      base64 = base64.substring(0, base64.length - 1);
  } else if (len % 3 === 1) {
      base64 = base64.substring(0, base64.length - 2);
  }

  return base64;
}
function getECPublicKeyFromPrivate(privateKey)
{
  var r=parseBigInt(BAtohex(privateKey),16);
  var curve = getSECCurveByName( "secp256r1" );
  var G = curve.getG();
  var P = G.multiply(r);
  return P;
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function submit_handler(event)
{
  return await processForm(event);
}
async function processForm(event){
 event.preventDefault();
 console.log("Submit called");

 var sk = derive_key(dh_key);
 console.log("Derived key: " + sk);
 var total=0;
 for(i=0;i<100;i++)
 {
   const  starttime=performance.now();
   var aesCtr = new aesjs.ModeOfOperation.ctr(sk, new aesjs.Counter(1));

   var $allPasswordBoxes = $("input[type='" + sgx_input + "']").not('[name="clone"]');
   if ($allPasswordBoxes !== undefined && $allPasswordBoxes.length > 0) {
     var password = $($allPasswordBoxes[0]).val();
     var textBytes = aesjs.utils.utf8.toBytes(password);
     var encrypted = aesCtr.encrypt(textBytes);
     $($allPasswordBoxes[0]).val(aesjs.utils.hex.fromBytes(encrypted) + gb_key);
     if ($allPasswordBoxes.length > 1) {
       if (password == $($allPasswordBoxes[1]).val()) {
         $($allPasswordBoxes[1]).val(aesjs.utils.hex.fromBytes(encrypted) + gb_key);
       } else {
         return false;
       }
     }
   }
   const endtime=performance.now();
   total+=endtime-starttime;
   await sleep(2);
 }
 const average_password_encryption=total/1.0;
 console.log('Average_Password_Encryption:'+average_password_encryption);
 // Do your asynchronous operations here
 if (signingkey) {
   const data = new FormData(event.target);
   const concatenatedString = [...data.values()].join(''); // Concatenate form values
   //var dataBuf = new TextEncoder().encode("12345678").buffer;
   var dataBuf = new TextEncoder().encode(concatenatedString).buffer;
   var publickey = getECPublicKeyFromPrivate(signingkey);

   let jwk = {
     kty: "EC",
     crv: "P-256",
     d: encode(signingkey),
     x: encode(hex2ba(publickey.getX().x.toString(16))),
     y: encode(hex2ba(publickey.getY().x.toString(16))),
     ext: true,
   };

   var importedskey = await window.crypto.subtle.importKey(
     'jwk',
     jwk,
     {
       name: 'ECDSA',
       namedCurve: 'P-256',
     },
     false,
     ['sign'],
   );

   var signature = await window.crypto.subtle.sign(
     {
       name: "ECDSA",
       hash: { name: "SHA-256" },
     },
     importedskey,
     dataBuf
   );

   //var transactionModifier = aesjs.utils.hex.fromBytes(new Uint8Array(dataBuf)) + aesjs.utils.hex.fromBytes(new Uint8Array(signature));
   var transactionModifier = aesjs.utils.hex.fromBytes(new Uint8Array(signature));
   // Append transactionModifier as a hidden input to the form
   $('<input>').attr({
     type: 'hidden',
     name: 'TransactionModifier',
     value: transactionModifier
   }).appendTo(event.target);
 }

 // Now that all asynchronous operations are complete, you can submit the form
 HTMLFormElement.prototype.submit.call(event.target);
 return false;
 //event.target.submit.click();
}
// Tried window.onload and DOMContentLoaded.
// They are not triggered fast enough for us.
$(document).ready(function() {
    // Check if sgx is enabled and send a message to background.js

    var counter = 0;
    var metas = document.getElementsByTagName('meta');
    console.log("TEEReceipt: before checking for SGX Enabled meta tag");
    for (var i=0; i<metas.length; i++) {
        if (metas[i].getAttribute("name") == "SGXEnabled") {
            sgx_input = metas[i].getAttribute("content");
            counter = counter + 1;
            console.log("SGXEnabled");
            break;
        }
    }

    //counter= counter + 1; // Uncomment to test non-SGX websites
    if(counter !== 0){ sgx_enabled = true; chrome.runtime.sendMessage({type: "SGXEnabled"});}
    else{sgx_enabled = false; chrome.runtime.sendMessage({type: "SGXNotEnabled"});}

    //chrome.runtime.sendMessage({type: "loaded"});
    chrome.runtime.onMessage.addListener( function(request, sender, sendResponse) {
        if(request.inject) {
            if(click == true) {
                chrome.runtime.sendMessage({type: "ProtectedModeOff"});
                protected_mode = false;
                var $allPasswordBoxes = $("input[type='" + sgx_input + "']");
                $("body > *").css("opacity", '1');
                var $clones = $('[name="clone"]');
                //var $tooltips = $(".tooltip");
                for(i = 0; i < $clones.length; i++){
                    //$($allPasswordBoxes[i]).val($($clones[i]).val());
                    $($clones[i]).remove();
                    //$($tooltips[i]).remove();
                }
                for(i = 0; i < $allPasswordBoxes.length; i++){
                    $($allPasswordBoxes[i]).css({ 'border': '' });
                }
                click = false;
            } else {
                //highlight the password fields
                chrome.runtime.sendMessage({type: "ProtectedModeOn"});
                protected_mode = true;
                console.log("TEEReceipt: protected mode is on for input of type " + sgx_input);
                var $allPasswordBoxes = $("input[type='" + sgx_input + "']");
                var $arr = $($allPasswordBoxes[0]).parents('div');
                var $parent_form = $($allPasswordBoxes[0]).closest('form');
                //$parent_form.submit(encrypt_submit);
                //$parent_form.submit(submit_handler);
                $('form').each(function(index, form) {
                  $(form).submit(submit_handler);
                });

                for(i = 0; i < $arr.length; i++) {
                    console.log("TEEReceipt: parent " + i + " " + $arr[i]);
                }

                for(i = 0; i < $allPasswordBoxes.length; i++) {

                    $($allPasswordBoxes[i]).css({ 'opacity': '1' });

                    var $clone = $($allPasswordBoxes[i]).clone();
                    $clone.attr("name","clone");

                    $($clone).css({
                        'width': $($allPasswordBoxes[i]).outerWidth(),
                        'height': $($allPasswordBoxes[i]).outerHeight(),
                        'border': 'green solid 2px',
                        'position': 'absolute',
                        'padding': '0px 0px',
                        'margin': '0px 0px',
                        'top': $($allPasswordBoxes[i]).offset().top,
                        'left': $($allPasswordBoxes[i]).offset().left
                    });
                    $($clone).attr('title', '');

                    $('body').append($($clone));
                    $($clone).tooltip({ position: {collision: "none", my: "left+10 center", at: "right center", using: function( position, feedback ) {
                        $( this ).css( position );
                        $( "<div>" ).addClass( feedback.vertical )
                                    .addClass( feedback.horizontal )
                                    .appendTo( this );
                    }}, content: "This input field will be encrypted before leaving your computer", offset: [-2, 10], opacity: 0.8});
                    $($clone).tooltip("open");

	                $('[name="clone"]').keyup(function() {
                        var $pass = $("input[type='" + sgx_input + "']").not('[name="clone"]');
                        var $clones = $('[name="clone"]');

                        for(i = 0; i < $clones.length; i++){
                            if($($clones[i]).attr('id') === $(this).attr('id')){
                                $($pass[i]).val($(this).val());
                            }
                        }
                    });

                    $("body > *").not('[name="clone"]').css("opacity", '0.5');
                    click = true;
                }
            }
        } else if (request.check === "SGXEnabled?") {
            if(sgx_enabled == false) {
                sendResponse({answer: "SGXNotEnabled"});
            } else if(sgx_enabled == true && protected_mode == true) {
                sendResponse({answer: "SGXEnabled&ProtectedMode"});
            } else if(sgx_enabled == true && protected_mode == false) {
                sendResponse({answer: "SGXEnabled&NotProtectedMode"});
            }
        } else if (request.shared_key !== undefined) {
            console.log("TEEReceipt: got the shared key");
            //alert("Got the shared key"+request.shared_key);
            dh_key = request.shared_key;
            gb_key = request.gb;
            console.log("Shared key: " + dh_key);
            console.log("G*b: " + gb_key);
            if(request.encrypted_signingkey!==undefined)
            {
                console.log("Encrypted_signingkey:"+request.encrypted_signingkey);
                var sk = derive_key( dh_key );
                console.log("Derived key: " + sk);
                var ret={signingkey:1};
                //sendResponse(ret);
                var aesCtr = new aesjs.ModeOfOperation.ctr(sk, new aesjs.Counter(1));
                var ret={signingkey:2};
                //sendResponse(ret);
                var ctBytes=aesjs.utils.hex.toBytes(request.encrypted_signingkey);
                console.log("Encrypted_signingkey bytes:"+ctBytes);
                var ret={signingkey:3};
                //sendResponse(ret);
                signingkey=aesCtr.decrypt(ctBytes);
                signingkey.reverse();
                var ret={signingkey:4};
                //sendResponse(ret);
                signingkeystr=aesjs.utils.hex.fromBytes(signingkey);
                var ret={signingkey:5};
                //sendResponse(ret);
                console.log("Signingkey:"+signingkey);

                //signTransactionModifier(signingkey);
                var ret={signingkey:10};
                sendResponse(ret);
            }
            else if(request.signingkey!==undefined)
            {
              console.log(request.signingkey);
              (async (skey) => {
              var dataBuf = new TextEncoder().encode("12345678").buffer
              var signature = await window.crypto.subtle.sign(
                  {
                      name: "ECDSA",
                      hash: {name: "SHA-256"},
                  },
                  skey,
                  dataBuf
              );
              return signature;
            })(aesjs.utils.hex.toBytes(request.signingkey)).then((v)=>{
                var $transactionmodifiers=$('[name="TransactionModifier"]');
                var dataBuf = new TextEncoder().encode("12345678").buffer;
                for(i=0;i<$transactionmodifiers.length;i++)
                {
                    $($transactionmodifiers[i]).val(aesjs.utils.hex.fromBytes(dataBuf)+aesjs.utils.hex.fromBytes(v));
                }
                console.log("TransactionModifier signature"+v);
              });

            }

            sendResponse({answer:"done","dh_key":dh_key,"gb_key":gb_key});
        }

    });
});

chrome.storage.onChanged.addListener(function(changes, namespace) {
    //location.reload();
});
