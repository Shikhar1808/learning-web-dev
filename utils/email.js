const nodemailer = require('nodemailer');
const dotenv = require('dotenv').config();

const sendEmail = async options => {
    // 1) Create a transporter
    //transporter is an object that sends email 
    const transporter = nodemailer.createTransport({
        host: process.env.EMAIL_HOST,
        port: process.env.EMAIL_PORT,
        auth: {
            user: process.env.EMAIL_USERNAME,
            pass: process.env.EMAIL_PASSWORD
        }
        //activate in gmail "less secure app" option
    })
    console.log(process.env.EMAIL_HOST,process.env.EMAIL_PORT,process.env.EMAIL_USERNAME,process.env.EMAIL_PASSWORD)
    
    // 2) Define the email options
    const mailOptions = {
        from: "Shikhar Saxena <saxena.shikhar05@gmail.com>",
        to: options.email,
        subject: options.subject,
        text: options.message,
    }


    // 3) Actually send the email
    await transporter.sendMail(mailOptions)
}
//In the above sendEmail function we are using nodemailer to send the email to the user with the options that we pass to the function as an argument
//we are awaiting the sendMail function to send the email beacuse it is an async function and we want to wait for the email to be sent before we move on to the next step

module.exports = sendEmail;