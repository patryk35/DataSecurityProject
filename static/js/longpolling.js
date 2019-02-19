function load_data() {
    let xhr = new XMLHttpRequest();
    xhr.open('GET', '/milewsp1/app/polling_data', false);
    xhr.onload = function () {
        if (this.responseText.length > 0) {
            console.log("aaaafddfaa");
            alert(this.responseText);
        }
    };
    xhr.send()
}

function long_polling() {
    let xhr = new XMLHttpRequest();
    xhr.open('POST', '/milewsp1/app/long_polling_notify', true);
    xhr.onload = function () {
        if (this.responseText == "newFile") {
            load_data();
        }
        setTimeout(long_polling, 1500)
    };
    xhr.send();
}

long_polling();

let submitButton = document.forms['registerForm']['send'];
submitButton.addEventListener("click", function (event) {
    event.preventDefault();
    if (doAllValidation()) {
        const formData = new FormData(document.getElementById('registerForm'));
        fetch("http://edi.iem.pw.edu.pl/chaberb/register/user/", {
            method: "post",
            body: formData
        }).then(resp => {
            console.log(resp.status); // not working -problems on backend site
        })
    }
})