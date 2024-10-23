const pass = $(".input-password .input-decoration");
const icon = $(".bi");
icon.on('click',()=>{
    const type = pass.attr('type')==='password' ? 'text':'password';
    pass.attr('type', type);
    icon.toggleClass('bi-eye-slash-fill');
    icon.toggleClass('bi-eye-fill');
}) 

$(".form").submit(function(e){
    e.preventDefault();
    const obj={
        username: $("input[name='username']").val(),
        password: $("input[name='password']").val()
    };
    axios.post("/submit",obj)
    .then(function(response){
        if(response.status === 200)
        {
            $(".error-message").css("color","#60ff40")
            $(".error-message").text(response.data.message);
        }
        adjustContainerHeight();
    }).catch(function(error){
        if(error.response)
        {
            $(".error-message").css("color","red")
            $(".error-message").text(error.response.data.message)
        }
        else
        {
            console.log("Error",error);
        }
        adjustContainerHeight();
    })
})
if($(".error-message").text!=='')
{
    $(".container").css("height","500px");
}
function adjustContainerHeight() {
    if ($(".error-message").text().length !== 0) {
        $(".container").css("height", "500px");
    }
}