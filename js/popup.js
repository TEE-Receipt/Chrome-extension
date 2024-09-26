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

document.addEventListener('DOMContentLoaded', function() {
     //document.getElementById("logout-div").style.display="none";
     var chkbxuserdrive=$("input[type='checkbox']")[0];
     chrome.storage.local.get(["usedrive"], function(data){
       chkbxuserdrive.checked=data.usedrive;
     });
     chkbxuserdrive.addEventListener('click', function(){
       chrome.runtime.sendMessage({usedrive:chkbxuserdrive.checked},function(){
         chrome.storage.local.set({usedrive:chkbxuserdrive.checked}, function (){
           console.log("use_drive:"+chkbxuserdrive.checked);
         });
       });
     });

    chrome.runtime.sendMessage({clicked : true});
    chrome.tabs.query({'active': true}, function (tabs) {
        console.log("TEEReceipt: tab query url " + tabs[0].url);

        chrome.storage.local.get({userUrls: []}, function(item) {
            console.log("TEEReceipt: storage get tab query url " + tabs[0].url);

            for (var i=0; i < item.userUrls.length; i++) {
                if(item.userUrls[i].URL === tabs[0].url){
                    console.log('TEEReceipt: DOMContentLoaded: URL match found');
                    var toggle = $("input[type='checkbox']")[1];
                    $(toggle).prop('checked', true);
                } else {
                    console.log('TEEReceipt: DOMContentLoaded: URL match not found');
                }
            }
        });
    });

    $("input[type='checkbox']")[1].addEventListener('click', function() {
        if($(this).is(':checked')) {
            var url;
            chrome.tabs.query({'active': true}, function (tabs) {
                url = tabs[0].url;
            });
            chrome.storage.local.get({userUrls: []}, function (result) {
                var userUrls = result.userUrls;
                userUrls.push({URL: url, disableScripts: true});
                chrome.storage.local.set({userUrls: userUrls}, function () {
                    chrome.storage.local.get('userUrls', function (result) {
                        console.log("TEEReceipt: user URLs " + result.userUrls)
                    });
                });
            });

        } else {
            chrome.tabs.query({'active': true}, function (tabs) {
                chrome.storage.local.get({userUrls: []}, function(items) {
                    for (var i=0; i < items.userUrls.length; i++) {
                        if(items.userUrls[i].URL === tabs[0].url){
                            items.userUrls.splice(i, 1);
                            chrome.storage.local.set(items, function() {});
                        }
                    }
                });
            });
        }
    });
}, false);

chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {

    console.log("TEEReceipt: in popup onMessageListener");
    if(request.type === "ProtectedModeOn"){
        document.getElementById("lock-icon").src = "/images/lock_huge.png";
        // console.log($("input[type='checkbox']").length);
    } else if(request.type === "ProtectedModeOff"){
        document.getElementById("lock-icon").src = "/images/grey_lock_huge.png";
        document.getElementById("content-text").textContent = "You can click the icon again to display the highlighted input fields";
    }
});
