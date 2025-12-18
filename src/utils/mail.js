import Mailgen from "mailgen";
import nodemailer from "nodemailer";

const sendEmail = async (options) => {

  const mailGenerator = new Mailgen({
    theme: "default",
    product: {
      name: "taskManager",
      link: "https://taskmanagerlink.com",
    },
  });

  // Generate email in HTML + Text
  const emailHtml = mailGenerator.generate(options.mailgenContent);
  const emailText = mailGenerator.generatePlaintext(options.mailgenContent);

  // Transporter
  const transporter = nodemailer.createTransport({
    host: process.env.MAIL_TRAP_SMTP_HOST,
    port: process.env.MAIL_TRAP_SMTP_PORT,
    auth: {
      user: process.env.MAIL_TRAP_SMTP_USER,
      pass: process.env.MAIL_TRAP_SMTP_PASS,
    },
  });

  const mail = {
    from: "easyShiv@gmail.com",
    to: options.email,
    subject: options.subject,
    text: emailText,
    html: emailHtml,
  };

  try {
    await transporter.sendMail(mail);
  } catch (error) {
    console.error(
      "Email service has failed! Check your Mailtrap credentials."
    );
    console.error(error);
  }
};

// ---------- Mailgen Templates -----------

const emailVerificationMailgenContent = (username, verificationURL) => {
  return {
    body: {
      name: username,
      intro: "Welcome to our app! We are excited to have you on board.",
      action: {
        instructions: "To verify your email, click the following button:",
        button: {
          color: "#1aae5a",
          text: "Verify your email",
          url: verificationURL,
        },
      },
      outro: "Need help? Just reply to this email.",
    },
  };
};

const forgotPasswordMailgenContent = (username, resetPasswordURL) => {
  return {
    body: {
      name: username,
      intro: "We got a request to change the password of your account.",
      action: {
        instructions: "Click the button below to reset your password:",
        button: {
          color: "#1aae5a",
          text: "Reset password",
          url: resetPasswordURL,
        },
      },
      outro: "If this wasn't you, you can ignore this email.",
    },
  };
};

export {
  emailVerificationMailgenContent,
  forgotPasswordMailgenContent,
  sendEmail,
};
