console.log("PhishGuard AI Loaded Successfully!");

const fileInput = document.getElementById("email_file");

const fileName = document.getElementById("file_name");

fileInput.addEventListener("change", function(){

    if(fileInput.files.length > 0){

        fileName.textContent = "✔ " + fileInput.files[0].name;

    }

});
