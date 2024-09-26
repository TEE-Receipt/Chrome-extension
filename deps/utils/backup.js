function saveLocal(filename,fileContent)
{
  var vLink = document.createElement('a'),
  vBlob = new Blob([fileContent], {type: "octet/stream"}),
  vName = filename+'.json',
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
