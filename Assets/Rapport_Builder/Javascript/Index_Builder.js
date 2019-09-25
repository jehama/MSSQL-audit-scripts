var ToC = "<h2 id='OTP'>On this page:</h2>";

var headers = document.getElementsByClassName("headers");
for (i = 0; i < headers.length; i++) {
  var current = headers[i];

  title = current.textContent;
  var type = current.tagName;
  link = "#" + current.getAttribute("id");


  var newLine

  if (type == 'H1') {
    newLine =
      "<ul>" +
      "<li>" +
      "<a href='" + link + "'>" +
      title +
      "</a>" +
      "</li>" +
      "</ul>";
  }
  if (type == 'H3') {
    newLine =
      "<ul style='padding-left: 60px;'>" +
      "<li>" +
      "<a href='" + link + "'>" +
      title +
      "</a>" +
      "</li>" +
      "</ul>";
  }

  ToC += newLine;
}

document.getElementById('ToC').innerHTML = ToC
