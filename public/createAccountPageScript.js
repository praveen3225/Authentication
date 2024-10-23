// Handle password toggle
$("#password-icon").on('click', function() {
    const passwordField = $("#password");  // Select the password field
    const type = passwordField.attr('type') === 'password' ? 'text' : 'password';
    passwordField.attr('type', type);  // Toggle type attribute between password and text
    $(this).toggleClass('bi-eye-slash-fill bi-eye-fill');  // Toggle eye icon
});

// Handle confirm password toggle
$("#confirm-password-icon").on('click', function() {
    const confirmPasswordField = $("#confirm-password");  // Select the confirm password field
    const type = confirmPasswordField.attr('type') === 'password' ? 'text' : 'password';
    confirmPasswordField.attr('type', type);  // Toggle type attribute between password and text
    $(this).toggleClass('bi-eye-slash-fill bi-eye-fill');  // Toggle eye icon
});

$(".form").on("submit", function(e) {
    e.preventDefault();
    const obj = {
        email: $("input[name='email']").val(),
        username: $("input[name='username']").val(),
        password: $("input[name='password']").val(),
        confirmpassword: $("input[name='confirm-password']").val()
    }
    axios.post("/create", obj)
    .then(function(response) {
        if (response.status === 400) {
            $(".error-message").css("color", "red");
            $(".error-message").text(response.data.message);
        } else if (obj.password === obj.confirmpassword) {
            $(".error-message").css("color", "#60ff40");
            $(".error-message").text(response.data.message);
            if (response.data.redirect) {
                // Redirect to the home page ("/") after a 3-second delay
                setTimeout(function() {
                    window.location.href = "/";
                }, 3000);  // Delay in milliseconds (3 seconds)
            }
        } else if (obj.password !== obj.confirmpassword) {
            $(".error-message").css("color", "red");
            $(".error-message").text(response.data.message);
        }

        // Check if the error message has text and adj ust the container height
        adjustContainerHeight();
    })
    .catch(function(error) {
        if (error.response) {
            $(".error-message").css("color", "red");
            $(".error-message").text(error.response.data.message);
        } else {
            console.log("Error", error);
        }

        // Check if the error message has text and adjust the container height
        adjustContainerHeight();
    });
});

// Function to adjust container height
function adjustContainerHeight() {
    if ($(".error-message").text().length !== 0) {
        $(".container").css("height", "570px");
    }
}
