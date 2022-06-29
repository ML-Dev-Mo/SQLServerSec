using System;
using System.Configuration;
using System.Windows.Forms;

namespace DBSec
{
    public partial class Form2 : Form
    {
        static int retry = 0;
        public Form2()
        {
            InitializeComponent();
            label2.Text = "";
        }
                                                                                     
        private void button1_Click(object sender, EventArgs e)
        {
            //try
            //{
            //    var mailRepository = new MailRepository(
            //               "imap.gmail.com",
            //               993,
            //               true,
            //               "bastanteb@gmail.com",
            //               "Hyp47$9?fGhVV3:k"
            //           );

            //    var emailList = mailRepository.GetAllMails("inbox");

            //    foreach (ActiveUp.Net.Mail.Message email in emailList)
            //    {
            //        Console.WriteLine("<p>{0}: {1}</p><p>{2}</p>", email.From, email.Subject, email.BodyHtml.Text);
            //        if (email.Attachments.Count > 0)
            //        {
            //            foreach (MimePart attachment in email.Attachments)
            //            {
            //                Console.WriteLine("<p>Attachment: {0} {1}</p>", attachment.ContentName, attachment.ContentType.MimeType);
            //            }
            //        }
            //    }

                //Pop3.Pop3Client client = new Pop3.Pop3Client();
                // client.Connect("pop.gmail.com", "dehghany.m", "d2DAbc1@#d2DAbc1", 995,false,true);
                // "pop.gmail.com", 995, true, "Username@gmail.com", "password");
                //SmtpClient SmtpServer = new SmtpClient("smtp.gmail.com");
                //SmtpServer.Port = 587;
                //SmtpServer.EnableSsl = true;
                //SmtpServer.Credentials = new System.Net.NetworkCredential("dehghany.m@gmail.com", "d2DAbc1@#d2DAbc1");
                //SmtpServer.Send("Me@m.com", "you@m.com", "Greeting", "Salute");
                //   SmtpClient c=new SmtpClient() 
                // }
                //catch(Exception ex)
                //{
                //    MessageBox.Show(ex.Message);
                //}

             if (retry++ > 3) { Application.ExitThread(); }
            if (textBox1.Text == "") { label2.Text="Please enter password"; }

           


            if (Utility.VerifyHash(textBox1.Text, ConfigurationManager.AppSettings.Get("cred")) == true)
            {
                this.Hide();
                Form1 frm = new Form1();
                frm.Show();
            }
            else
            {
                label2.Text = "Wrong Pass!!";
            }
        }

       

        private void textBox1_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.KeyCode == Keys.Enter)
                button1.PerformClick();
        }
    }
}
