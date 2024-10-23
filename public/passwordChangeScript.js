let isEmailVerified = false;

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

$(".form").submit(function(e){
    e.preventDefault(); // Prevent full page reload on form submit
    if(!isEmailVerified)
    {
        const obj = {
            email: $("input[name='email']").val(),
        };
        axios.post("/verify", obj)
        .then(function(response){
            
            if(response.status===200)
            {
                console.log(response.data);
                $(".error-message").css("color","#60ff40")
                $(".error-message").text(response.data.message)
                $(".input-email").addClass("hidden")
                $(".input-password").removeClass("hidden")
                $(".input-password").removeClass("hidden")
                isEmailVerified = true
            }
            else
            {
                $(".error-message").css("color","red")
                $(".error-message").text(response.data.message)
            }
        })
        .catch(function(error){
            console.error("Error submitting form:", error);
        });
    }
    else
    {
        const obj = {
            password : $("input[name='password']").val(),
            email : $("input[name='email']").val()
        }
        confirmPassword = $("input[name='confirm-password']").val()
        if(obj.password===confirmPassword)
        {
            axios.patch(("/change"),obj)
            .then(function(response){
                if(response.status===200)
                {
                    $(".error-message").css("color","#60ff40")
                    $(".error-message").text(response.data.message)
                    isEmailVerified = false
                    setTimeout(function(){
                        window.location.href = "/"
                    },3000)

                }
            }).catch(function(error)
            {
                console.log(error);
            });
        }
        else{
            $(".error-message").css("color","red")
            $(".error-message").text("Passwords do not match")
        }
    }
});

