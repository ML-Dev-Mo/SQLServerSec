using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Configuration;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace DBSec
{
    public partial class ChangePassword : Form
    {
        public ChangePassword()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            var config = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None);
     


            label6.Text= label5.Text = label4.Text = "";
            if(textBox1.Text==""||textBox2.Text==""||textBox3.Text=="")
            {

                label4.Text = "Please enter all fields";
                return;
            }
            if (textBox2.Text!=textBox3.Text)
            {
                label5.Text="not same";return;
            }
            else
            {

                if(Utility.VerifyHash(textBox1.Text, config.AppSettings.Settings["cred"].Value) != true)
                {
                    label4.Text = "wrong pass";
                    return;
                }
                else
                {
                   
                  

                    config.AppSettings.Settings["cred"].Value = Utility.MakeHash(textBox2.Text);
                    config.Save(ConfigurationSaveMode.Modified);

                    ConfigurationManager.RefreshSection("appSettings");
                    label6.Text = "Successful";

                }
            }
        }

        private void ChangePassword_Load(object sender, EventArgs e)
        {
            label6.Text= label4.Text = label5.Text = "";
        }
    }
}
