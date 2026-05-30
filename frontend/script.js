document.addEventListener("DOMContentLoaded", () => {

  const sendBtn =
  document.getElementById("sendBtn");

  const loading =
  document.getElementById("loading");

  const result =
  document.getElementById("result");

  sendBtn.addEventListener(
    "click",

    async () => {

      const emailsText =
      document.getElementById("emails").value;

      const subject =
      document.getElementById("subject").value;

      const message =
      document.getElementById("message").value;

      const attachment =
      document.getElementById("attachment").files[0];

      if(!emailsText || !subject || !message){

        alert("Please fill all fields");

        return;
      }

      const emails = emailsText
      .split("\n")
      .map(email => email.trim())
      .filter(email => email !== "");

      loading.style.display = "block";

      result.innerHTML = "";

      try{

        const formData = new FormData();

        formData.append(
          "emails",
          JSON.stringify(emails)
        );

        formData.append(
          "subject",
          subject
        );

        formData.append(
          "message",
          message
        );

        if(attachment){

          formData.append(
            "attachment",
            attachment
          );

        }

        const response = await fetch(
          "https://bulk-email-sender-uaig.onrender.com/send-emails",
          {
            method:"POST",
            credentials:"include",
            body:formData
          }
        );

        const data =
        await response.json();

        loading.style.display = "none";

        if(data.success){

          result.innerHTML =
          "✅ Emails Sent Successfully";

        }else{

          result.innerHTML =
          "❌ Failed To Send Emails";

        }

      }catch(error){

        console.log(error);

        loading.style.display = "none";

        result.innerHTML =
        "❌ Failed To Send Emails";

      }

    }

  );

});