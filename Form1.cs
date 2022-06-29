using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Data.SqlClient;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Web;
using System.Security;
using System.Configuration;
using System.Xml;
using System.Threading;
using System.Diagnostics;

namespace DBSec
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();

        }

        private async void Button1_Click(object sender, EventArgs e)
        {
            label30.Text =  "";
            button1.Enabled = false;
            label2.Text = "please wait...";
            label30.Text+= await BackupCertificate(txt_ServerIP.Text, txt_DB.Text, Utility.DBPass, 
                textBox1.Text);

           
            
            label30.Text += BackupDataBase(txt_ServerIP.Text, txt_DB.Text, Utility.DBPass, 
                textBox1.Text);
            //if (checkBox1.Checked == true && textBox12.Text != "")
            //{
            //    label30.Text += Utility.PutFileInFTP(localFilePath: textBox1.Text + "\\" +
            //        Utility.PharmacySerial + ".pvk", password: Utility.ToSecureString(textBox12.Text), pharmacySerial:
            //        Utility.PharmacySerial) + "\n";

            //    label30.Text += await Utility.PutFileInFTP(localFilePath: textBox1.Text + "\\" +
            //        Utility.PharmacySerial + ".cer", password: Utility.ToSecureString(textBox12.Text), pharmacySerial:
            //        Utility.PharmacySerial) + "\n";

            //    label30.Text += await Utility.PutFileInFTP(localFilePath: textBox1.Text + "\\" +
            //        Utility.PharmacySerial + ".key", password: Utility.ToSecureString(textBox12.Text), pharmacySerial:
            //        Utility.PharmacySerial) + "\n";
            //}
            label2.Text = "";
            button1.Enabled = true;
        }
        private async Task<string> BackupDataBase(string IP, string DB, SecureString pass, string pathToBackup)
        {
            var constr = Utility.MakeConnectionStr(IP, DB, pass);
            var res = await Utility.TestDbConnection(constr);
            if (res != "Ok")
            {
                return ("Error in connecting database " + res);

            }
            using (SqlConnection conn = new SqlConnection(constr))
            {

                try
                {
                    await conn.OpenAsync();
                    var comm = string.Format($@"use master; OPEN MASTER KEY DECRYPTION BY PASSWORD = '{Utility.ToInsecureString(pass)}';BACKUP DATABASE {DB} TO DISK=N'{pathToBackup}\{DateTime.Now.ToShortDateString().Replace('/', '-')}.bak';");
                    SqlCommand command = new SqlCommand(comm, conn);
                    command.ExecuteNonQuery();
                    conn.Close();
                    return "Backup has copied successfuly";
                }
                catch (Exception ex)
                {

                    return ex.Message;
                }
            }
        }
        private async Task<string> BackupCertificate(string IP, string DB, SecureString pass, string pathToBackup)
        {
            var constr = Utility.MakeConnectionStr(IP, DB, pass);
            var res = await Utility.TestDbConnection(constr);
            if (res != "Ok")
            {
                return "Connection failure!";
            }
            using (SqlConnection conn = new SqlConnection(constr))
            {
 
                try
                {
                    string returnMessage = "";
                    await conn.OpenAsync();
                    var comm = string.Format($@"use master;
                                                    OPEN MASTER KEY DECRYPTION BY PASSWORD = N'{Utility.ToInsecureString(pass)}';                                                    
                                                    BACKUP CERTIFICATE {DB} TO FILE = N'{pathToBackup}\{DB}.cer'
                                                    WITH PRIVATE KEY
                                                    (FILE = N'{pathToBackup}\{DB}.pvk',ENCRYPTION BY PASSWORD = N'{Utility.passPhrase}')"
                                                     );
                    SqlCommand command = new SqlCommand(comm, conn);
                    command.ExecuteNonQuery();
                    returnMessage+= "Certificate copied successfuly\n";
                    comm = string.Format($@"BACKUP MASTER KEY TO FILE = N'{pathToBackup+"\\"+DB}.key'  ENCRYPTION BY PASSWORD = '{pass}';");
                    command = new SqlCommand(comm, conn);
                    command.ExecuteNonQuery();
                    conn.Close();
                    returnMessage+= "Master Key has copied successfuly\n";
                    return returnMessage;
                }
                catch (Exception ex)
                {

                    return ex.Message;
                }
            }
        }

        private async Task<string> EncryptDB(string IP, string DB, SecureString pass)
        {
            try
            {
                SqlConnection conn = new SqlConnection(Utility.MakeConnectionStr(IP, DB, pass));
                
                SqlCommand command;
                try
                {
                    command = new SqlCommand($@"USE master;
                                                      CREATE MASTER KEY ENCRYPTION BY PASSWORD = '{Utility.ToInsecureString(pass)}'", conn);
                    await conn.OpenAsync();
                    await command.ExecuteNonQueryAsync();
                    
                }
                catch  {  }
                finally { conn.Close(); }


                command = new SqlCommand(string.Format($@"
                                                      USE master;
                                                      
                                                      CREATE CERTIFICATE {Utility.DbName} WITH SUBJECT = 'My DEK Certificate';
                                                      USE {DB};
                                                      CREATE DATABASE ENCRYPTION KEY
                                                      WITH ALGORITHM = AES_128
                                                      ENCRYPTION BY SERVER CERTIFICATE {Utility.DbName};  
                                                      ALTER DATABASE {DB}
                                                      SET ENCRYPTION ON;"), conn);
                
                await conn.OpenAsync();
                await command.ExecuteNonQueryAsync();
                conn.Close();
                return "Done!";

               
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }

        private async Task<string> RestoreCertificateAndDb(string dbNameToRecover,string IP, string DB, SecureString pass, string masterKeyPath, string certificatePath, string privateKeyPath, string DbPath, string ldfPath, string fileType)
        {


            try
            {

                SqlConnection conn = new SqlConnection(Utility.MakeConnectionStr(IP, DB, pass));
                string textCommad;
                if (fileType == "mdf")
                {

                    textCommad = string.Format($@"use master;

                              RESTORE MASTER KEY   
                              FROM FILE = N'{masterKeyPath}'   
                              DECRYPTION BY PASSWORD = '{Utility.ToInsecureString(pass)}'   
                              ENCRYPTION BY PASSWORD = '{Utility.ToInsecureString(pass)}';  
                              OPEN MASTER KEY DECRYPTION BY PASSWORD = '{Utility.ToInsecureString(pass)}'  
                              use master;
                              create certificate {Utility.DbName}
                              from file = N'{certificatePath}'
                              with private key
                                    ( file = N'{privateKeyPath}'
                                        , decryption by password ={Utility.passPhrase}
                                    )
                              CREATE DATABASE {dbNameToRecover}   
                              ON (FILENAME = '{DbPath}'),   
                                 (FILENAME = '{ldfPath}')   
                              FOR ATTACH;");
                }
                else
                {
                    textCommad = string.Format($@"use master;
                              RESTORE MASTER KEY   
                              FROM FILE = N'{masterKeyPath}'   
                              DECRYPTION BY PASSWORD = '{dbNameToRecover}'
                              ENCRYPTION BY PASSWORD = '{dbNameToRecover}';  
                              OPEN MASTER KEY DECRYPTION BY PASSWORD = '{dbNameToRecover}'  
                              use master;
                              create certificate {Utility.DbName}
                              from file = N'{certificatePath}'
                              with private key
                                    ( file = N'{privateKeyPath}'
                                        , decryption by password = {Utility.passPhrase}
                                    )

                              RESTORE DATABASE {5} 

                              FROM DISK = '{3}' WITH REPLACE");
                }
                SqlCommand command = new SqlCommand(textCommad, conn);
                await conn.OpenAsync();
                command.ExecuteNonQuery();
                conn.Close();
                return "Success";
                

            }
            catch (Exception ex)
            {
                return ex.Message;
            }


        }

        public struct dataOfTiny
        {
           public  string DataPartition, SerialNumber;
            public dataOfTiny(string dataPartition,string serialNumber)
            {
                DataPartition = dataPartition;
                SerialNumber = serialNumber;
            }
        };
        public dataOfTiny ReadFromTiny()
        {
            
            Tn.ServerIP = "127.0.0.1";
            Tn.NetWorkINIT = true;
            if (Tn.TinyErrCode == 0)
            {
                Tn.UserPassWord = TinyCode.Text;
                Tn.ShowTinyInfo = true;
                //var data = Tn.DataPartition.Split('@');
                var serial = Tn.SerialNumber.Split('-');
                var serialwithoutdash = string.Join("", serial);
                return new dataOfTiny(Tn.DataPartition, serialwithoutdash);
            }
            else
            {
                Tn.Initialize = true;
                if (Tn.TinyErrCode == 0)
                {

                    Tn.UserPassWord = TinyCode.Text;
                    Tn.ShowTinyInfo = true;
                    Tn.UserPassWord = TinyCode.Text;
                    Tn.ShowTinyInfo = true;
                    if (Tn.DataPartition == "") return new dataOfTiny("error","error");
                    var serial = Tn.SerialNumber.Split('-');
                    var serialwithoutdash = string.Join("", serial);
                    return new dataOfTiny(Tn.DataPartition, serialwithoutdash);
                }
                else
                {
                    return new dataOfTiny("error","error");
                }
            }
        }
        private void Form1_Load(object sender, EventArgs e)
        {
                // Bitmap image = new Bitmap(@"C:\Users\Administrator\Downloads\d_helix-css-gif-_50fps-selective_-1a.gif");
            //image.MakeTransparent();
            //pictureBox1.Image = image;
          //  System.Configuration.ConfigurationManager.appSetting;
            radioButton2.Checked = true;
           // SecTab.Enabled = false;
           panel3.Enabled =  button8.Enabled ;
           label19.Text= label31.Text=  label30.Text= label26.Text=label27.Text=label28.Text=  label22.Text= label2.Text =label7.Text= label3.Text =label10.Text= label11.Text=label12.Text= label9.Text= label20.Text= label21.Text="";
            // pictureBox1.Location = new Point(0, 0);
        
          
        }

        private void Button2_Click(object sender, EventArgs e)
        {
            DialogResult res = folderBrowserDialog1.ShowDialog();
            if (res == DialogResult.OK)
                textBox1.Text = folderBrowserDialog1.SelectedPath;
        }

        private void Button5_Click(object sender, EventArgs e)
        {

            try
            {
                if ((string.IsNullOrEmpty(txt_DB.Text.Trim())) || (string.IsNullOrEmpty(txt_ServerIP.Text.Trim())))
                {
                    MessageBox.Show("Please fill in required fields!");
                }
                else
                {
                    
                    // var srvIP = txt_ServerIP.Text.Replace("\\", "\");
                    var tr= txt_ServerIP.Text.Contains("\\");
                    var s = @txt_ServerIP.Text;
                     var rawConstr ="provider=sqloledb.1;"+ Utility.MakeConnectionStr(s, txt_DB.Text,
                        Utility.DBPass);

                    //var res = await Utility.TestDbConnection(rawConstr);
                    //if (res != "Ok")
                    //{
                    //    MessageBox.Show("خطا در اتصال به دیتابیس " + res);
                    //    return;
                    //}

                  

                    string conStr = Utility.Encrypt(rawConstr);
                

                    ConfigXmlDocument configXmlDocument = new ConfigXmlDocument();
                    configXmlDocument.Load(textBox3.Text);
                    var c = configXmlDocument.DocumentElement.GetElementsByTagName("appSettings").Item(0).ChildNodes;
                  
                    bool found = false;
                    foreach (XmlNode node in configXmlDocument.DocumentElement.GetElementsByTagName("appSettings").Item(0).ChildNodes)
                    {
                        if (node.Attributes["key"].Value == "conn")
                        {
                            found = true;
                            node.Attributes["value"].Value = conStr;
                        }

                    }
                    if (found != true)
                    {
                        configXmlDocument.DocumentElement.GetElementsByTagName("appSettings").Item(0).InnerXml = string.Format("<add key=\"conn\" value=\"{0}\" />", conStr) + configXmlDocument.DocumentElement.GetElementsByTagName("appSettings").Item(0).InnerXml;
                    }


                    //foreach (XmlNode node in configXmlDocument.DocumentElement.GetElementsByTagName("userSettings").Item(0).ChildNodes)
                    //   "TinyServerID"

                    configXmlDocument.Save(textBox3.Text);
                    label20.Text = "Server's config created";

                    var newnode = configXmlDocument.DocumentElement.GetElementsByTagName("Sinad.Properties.Settings").Item(0).ChildNodes[6];
                    newnode.InnerXml = "<value>" + textBox9.Text + "</value>";

                    configXmlDocument.Save(textBox3.Text + ".client");
                    label21.Text = "Client's config created";

                    label19.Text = "\u2714";


                }
            }catch(Exception ex)
            { MessageBox.Show(ex.Message); }
        }


        private void Button6_Click(object sender, EventArgs e)
        {
           try
            {
                //dataOfTiny dataOfTiny;
                //if (radioButton3.Checked)
                //{
                //    dataOfTiny = ReadFromTiny();
                //}
                //else
                //{
                   
                //    dataOfTiny.DataPartition = "'@" + textBox14.Text;

                //    dataOfTiny.SerialNumber = "";
                //}

                //if (dataOfTiny.DataPartition == "error")
                //{
                //    panel1.Enabled = false;
                //    MessageBox.Show("Error in reading!");
                //    TinyCode.BackColor = Color.Red;
                //    SecTab.Enabled = false;
                //    button6.BackColor = Color.Red;
                //}
                //else
                //{

                    panel1.Enabled = true;
                    //Utility.DBPass = Utility.ToSecureString(dataOfTiny.DataPartition.Split('@')[1]);
                    //Utility.passPhrase = Utility.ToSecureString(dataOfTiny.DataPartition.Split('@')[1]);
                    //Utility.PharmacySerial = Utility.ToSecureString(dataOfTiny.SerialNumber);
                    
                    SecTab.Enabled = true;
                    panel3.Enabled = false;
                    button6.BackColor = Color.Green;
                    TinyCode.BackColor = Color.Lime;
                    textBox14.BackColor = Color.Lime;

              //  }
            }

            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }

        }

        private void Txt_ServerIP_TextChanged(object sender, EventArgs e)
        {
            txt_DB.Items.Clear();
            txt_DB.Text = "";
            //SecTab.Enabled = false;
        }

        private async void Button8_Click(object sender, EventArgs e)
        {

            Utility.DbName = txt_DB.Text;
            if ((string.IsNullOrEmpty(txt_DB.Text.Trim())) || (string.IsNullOrEmpty(txt_ServerIP.Text.Trim())))
            {
                MessageBox.Show("Please fill in all the required fields!");
            }
            else
            {
                var rawConstr = Utility.MakeConnectionStr(txt_ServerIP.Text, txt_DB.Text,
                    Utility.DBPass);

                var res =await Utility.TestDbConnection(rawConstr);
                if (res != "Ok")
                {
                    label10.ForeColor = Color.Red;
                    SecTab.Enabled = false;
                    label10.Text="Error in connecting to Db " + res;
                    button8.BackColor = Color.Red;
                    panel3.Enabled = true;
                    label7.Text = "Please change your password first!";
                    return;
                }
                else
                {

                    var isEncrypted = await CheckForDbEncrypted(txt_ServerIP.Text, txt_DB.Text, Utility.DBPass);
                    SqlConnection conn = new SqlConnection(rawConstr);
//                    SqlCommand command = new SqlCommand(@"use master;


//select
//    database_name = d.name,
//    dek.encryptor_type,
//    cert_name = c.name
//from sys.dm_database_encryption_keys dek
//left join sys.certificates c
//on dek.encryptor_thumbprint = c.thumbprint
//inner join sys.databases d
//on dek.database_id = d.database_id;", conn);

                    var dataAdapter = new SqlDataAdapter($@"use master;
                                                            select
                                                                database_name = d.name,
  
                                                                cert_name = c.name
                                                            from sys.dm_database_encryption_keys dek
                                                            left join sys.certificates c
                                                            on dek.encryptor_thumbprint = c.thumbprint
                                                            inner join sys.databases d
                                                            on dek.database_id = d.database_id where d.name = '{Utility.DbName}';", conn);

                    var commandBuilder = new SqlCommandBuilder(dataAdapter);
                    var ds = new DataSet();
                    dataAdapter.Fill(ds);
                    dataGridView1.ReadOnly = true;
                    dataGridView1.DataSource = ds.Tables[0];
                   // dataGridView1.DataSource = command.ExecuteReader();
                    //abel10.BackColor = Color.
                    //button8.BackColor = Color.Lime;
                    panel3.Enabled = false;
                    //label10.ForeColor = Color.Lime;
                    //SecTab.Enabled = true;
                    if (isEncrypted)
                    {
                        label10.Text = "\u2714";
                        label10.ForeColor = Color.Green;
                    }
                    else
                    {
                        label10.Text = "\u274C";
                        label10.ForeColor = Color.Red;
                    }
                }
            }
        }




        private async Task<Boolean> CheckForDbEncrypted(string IP, string DB, SecureString pass)
        {

            var constr = Utility.MakeConnectionStr(IP, DB, pass);
            SqlConnection conn = new SqlConnection(constr);
            SqlCommand command;
            command = new SqlCommand(string.Format(@"SELECT
                                                    db.name,
                                                    db.is_encrypted,
                                                    dm.encryption_state,
                                                    dm.percent_complete,
                                                    dm.key_algorithm,
                                                    dm.key_length
                                                    FROM
                                                    sys.databases db
                                                    LEFT OUTER JOIN sys.dm_database_encryption_keys dm
                                                        ON db.database_id = dm.database_id WHERE name = '{0}'; ", DB), conn);
            await conn.OpenAsync();
            var dbreader = await command.ExecuteReaderAsync();
            dbreader.Read();
            var test =(bool) dbreader[1];
            conn.Close();
            if (test == true)
            {
                var res = MessageBox.Show("This db has been encrypted already!");
                conn.Close();
                return true;
            }
 

            command = new SqlCommand($"use master;select COUNT(*) from sys.certificates where name='{Utility.DbName}'", conn);
            await conn.OpenAsync();
            var reader = await command.ExecuteReaderAsync();
            reader.Read();
            if ((int)reader[0] > 0)
            {
                conn.Close();
                var res = MessageBox.Show("certificate exists on this system. Do you want to delete it?", "", MessageBoxButtons.YesNo);
                if (res != DialogResult.Yes)
                    return true;
                else
                {
                    command = new SqlCommand($"use master;drop certificate {Utility.DbName};drop master key;", conn);
                    await conn.OpenAsync();
                    command.ExecuteNonQuery();
                    MessageBox.Show("Deleted successfuly");
                    conn.Close();
                }
            }
            return test;

        }

        private async void Button7_Click(object sender, EventArgs e)
        {
            button7.Enabled = false;
            label26.Text=  await EncryptDB(txt_ServerIP.Text, txt_DB.Text,
                                Utility.DBPass);
            label27.Text= await BackupCertificate(txt_ServerIP.Text, txt_DB.Text,
                                Utility.DBPass,textBox5.Text);
            label28.Text = "لطفا منتظر بمانید";
            label28.Text= await BackupDataBase(txt_ServerIP.Text, txt_DB.Text,
                               Utility.DBPass, textBox5.Text);
            label12.Text = "\u2714";
            button7.Enabled = true;
            button8.PerformClick();
        }

        private void Button3_Click_1(object sender, EventArgs e)
        {
            openFileDialog1.Filter = "key files(*.key)|*.key";
               var res= openFileDialog1.ShowDialog();
            if (res == DialogResult.OK)
                textBox2.Text = openFileDialog1.FileName;
        }

        private void Button11_Click(object sender, EventArgs e)
        {
            DialogResult res = folderBrowserDialog1.ShowDialog();
            if (res == DialogResult.OK)
                textBox5.Text = folderBrowserDialog1.SelectedPath;
        }

        private void Button12_Click(object sender, EventArgs e)
        {
            openFileDialog1.Filter = "certificate files(*.cer)|*.cer";
            var res= openFileDialog1.ShowDialog();
            if (res == DialogResult.OK)
                textBox6.Text = openFileDialog1.FileName;
        }

        private void Button13_Click(object sender, EventArgs e)
        {
            openFileDialog1.Filter = "bak files(*.bak)|*.bak";
            var res= openFileDialog1.ShowDialog();
            if(res==DialogResult.OK)
                textBox7.Text = openFileDialog1.FileName;
        }

        private async void Button9_Click(object sender, EventArgs e)
        {
            button9.Enabled = false;
            var ldfpath =textBox7.Text.Remove(textBox7.Text.Length-3,3)+"ldf";
            var filetype = "mdf";
            if (radioButton1.Checked == true) filetype = "mdf"; else filetype = "bak";
            label31.Text = "Please wait!";
            label31.Text= await RestoreCertificateAndDb(textBox13.Text, txt_ServerIP.Text,"master", Utility.DBPass,textBox2.Text
                ,textBox6.Text,textBox8.Text,textBox7.Text,ldfpath,filetype);
            button9.Enabled = true;
        }

        private void Button14_Click(object sender, EventArgs e)
        {
            openFileDialog1.Filter = "private key files(*.pvk)|*.pvk";
            var res = openFileDialog1.ShowDialog();
            if (res == DialogResult.OK)
                textBox8.Text = openFileDialog1.FileName;
        }

        private async void button15_Click(object sender, EventArgs e)
        {



            //// button8.BackColor = Color.Green;
            try
            {
                ChangePassAndRenameSa(txt_ServerIP.Text, txt_DB.Text,Utility.ToSecureString(textBox4.Text),"sa");
                await DisableAllUserButSa(txt_ServerIP.Text, txt_DB.Text, Utility.DBPass);
            }catch(Exception ex)
            {
                label7.Text = ex.Message;
            }



        }
        private void  ChangePassAndRenameSa(string address, string db, SecureString pass, string newSaName)
        {
            try
            {
                SqlConnection conn = new SqlConnection(Utility.MakeConnectionStr(address, db, pass, "sa"));
                conn.Open();
                SqlCommand comm = new SqlCommand(

                  string.Format($@"USE MASTER
                                  ALTER LOGIN sa WITH NAME = {newSaName},
                                  PASSWORD = '{0}'; ", Utility.ToInsecureString(Utility.DBPass)), conn);


                comm.ExecuteNonQuery();
                textBox4.BackColor = Color.Lime;
                label11.Text = "\u2714";

                conn.Close();
            }
            catch(Exception ex) {

                SqlConnection conn = new SqlConnection(Utility.MakeConnectionStr(address, db, pass, newSaName));
                conn.Open();
                SqlCommand comm = new SqlCommand(

                  string.Format(@"USE MASTER
                                  ALTER LOGIN BastaniTeb  WITH NAME = BastaniTeb,
                                  PASSWORD = '{0}'; ", Utility.ToInsecureString(Utility.DBPass)), conn);


                comm.ExecuteNonQuery();
                textBox4.BackColor = Color.Lime;
                label11.Text = "\u2714";

                conn.Close();
               
            }

        }
        public async Task DisableAllUserButSa(string address,string db,SecureString pass)
        {
            try
            {
                string strCommand =string.Format(@"SELECT 'use master;Deny connect to ' + QUOTENAME(sp.name) 
                                  FROM sys.server_principals sp
                                  WHERE sp.principal_id > 100   
                                  AND sp.is_disabled = 0
                                  AND sp.type IN ('G','s','u') and name<> '##MS_PolicyTsqlExecutionLogin##' ;", db);
             
                SqlConnection conn = new SqlConnection(Utility.MakeConnectionStr(address, db, pass));
                
                SqlCommand command = new SqlCommand(strCommand, conn);
                await conn.OpenAsync();
                var reader=command.ExecuteReader();
               
                List<string> commands = new List<string>();
                while (reader.Read())
                {
                    commands.Add(reader[0].ToString());
                   
                }
                strCommand = string.Format(@"SELECT 'use master;ALTER LOGIN ' + QUOTENAME(sp.name) + ' DISABLE;'
                                                FROM sys.server_principals sp
                                                WHERE sp.principal_id > 100
                                                    AND sp.is_disabled = 0
                                                    AND sp.type IN ('U', 'S');");
                command = new SqlCommand(strCommand, conn);
                reader.Close();
                reader = command.ExecuteReader();

               
                while (reader.Read())
                {
                    commands.Add(reader[0].ToString());

                }
                conn.Close();
                conn.Open();
                SqlCommand alterLoginCommand;
                commands.ForEach(c =>
                {
                    alterLoginCommand = new SqlCommand(c, conn);
                    alterLoginCommand.ExecuteNonQuery();
                });

                
                
               
                MessageBox.Show("All users has disabled");
                conn.Close();
            }catch(Exception ex)
            {
                MessageBox.Show(ex.Message);
            }

        }

        private void button4_Click(object sender, EventArgs e)
        {
           openFileDialog1.Filter = "config files(*.config)|*.config|All files(*.*)|*.*";
            openFileDialog1.FilterIndex = 2;
            var res=openFileDialog1.ShowDialog();

            if (res == DialogResult.OK)
            {
                textBox3.Text = openFileDialog1.FileName;
                textBox9.Text = Utility.GetLocalIPAddress();
            }
        }

        private void radioButton1_CheckedChanged(object sender, EventArgs e)
        {
            openFileDialog1.Filter = "DB files(*.mdf)|*.mdf";
        }

        private void radioButton2_CheckedChanged(object sender, EventArgs e)
        {
            openFileDialog1.Filter = "Backup files(*.bak)|*.bak";
        }

       
        private void comboBox1_Enter(object sender, EventArgs e)
        {
            try
            {
                txt_DB.Text = "";
                txt_DB.Items.Clear();
                Utility.DBPass = Utility.ToSecureString(textBox15.Text);
               
                string constr = Utility.MakeConnectionStr(txt_ServerIP.Text, "Master", Utility.DBPass);
                SqlConnection conn = new SqlConnection(constr);
                SqlCommand command = new SqlCommand("SELECT name FROM master.sys.databases", conn);
                conn.Open();
                var reader = command.ExecuteReader();
                while (reader.Read())
                {
                    txt_DB.Items.Add(reader[0]);
                }
                conn.Close();
                button8.Enabled = true;
                
            }
            catch (Exception ex)
            {
                MessageBox.Show("There is a problem. Check the connection");
                panel3.Enabled = true;
                button8.Enabled = false;
            }
        }

      
        private async void button16_Click(object sender, EventArgs e)
        {
            await PutMaintenancePlan(txt_ServerIP.Text, txt_DB.Text, Utility.DBPass,textBox11.Text,textBox10.Text);
        }
        private async Task PutMaintenancePlan(string address,string db,SecureString pass,string pathToBackUp,string mirrorBackUp)
        {
            try
            {
                var textCommand = string.Format(@"USE msdb ;  
                                                    EXEC dbo.sp_add_job  
                                                        @job_name = N'Weekly Sinad Data Backup' ;  
                                                    EXEC sp_add_jobstep  
                                                        @job_name = N'Weekly Sinad Data Backup',  
                                                        @step_name = N'Set database to read only',  
                                                        @subsystem = N'TSQL',  
                                                        @command = N'BACKUP DATABASE Sinad TO DISK=''d:\\ertest.bak''',   
                                                        @retry_attempts = 5,  
                                                        @retry_interval = 5 ;  
                                                    EXEC dbo.sp_add_schedule  
                                                        @schedule_name = N'RunWeekly',  
                                                        @freq_type = 8, 
                                                        @freq_interval=1, 
                                                        @active_start_time = 171500 ;  
                                                    USE msdb ;  
                                                    EXEC sp_attach_schedule  
                                                        @job_name = N'Weekly Sinad Data Backup',  
                                                        @schedule_name = N'RunWeekly';  
                                                    EXEC dbo.sp_add_jobserver  
                                                        @job_name = N'Weekly Sinad Data Backup';  
  
                                                    EXEC dbo.sp_add_job  
                                                        @job_name = N'Daily Sinad Data Backup' ;  
  
                                                    EXEC sp_add_jobstep  
                                                        @job_name = N'Daily Sinad Data Backup',  
                                                        @step_name = N'Set database to read only',  
                                                        @subsystem = N'TSQL',  
                                                        @command = N'BACKUP DATABASE Sinad  TO DISK=''d:\\ertest.bak'' WITH DIFFERENTIAL',   
                                                        @retry_attempts = 5,  
                                                        @retry_interval = 5 ;  
  
                                                    EXEC dbo.sp_add_schedule  
                                                        @schedule_name = N'RunDaily',  
                                                        @freq_type = 4,  
                                                        @freq_interval=1,

                                                    @active_start_time = 171500 ;  
                                                    USE msdb ;  
  
                                                    EXEC sp_attach_schedule  
                                                        @job_name = N'Daily Sinad Data Backup',  
                                                        @schedule_name = N'RunDaily';  
  
                                                    EXEC dbo.sp_add_jobserver  
                                                        @job_name = N'Daily Sinad Data Backup';");
                SqlConnection conn = new SqlConnection(Utility.MakeConnectionStr(address, db, pass));
                SqlCommand command = new SqlCommand(textCommand, conn);
                await conn.OpenAsync();
                command.ExecuteNonQuery();
                conn.Close();
                MessageBox.Show("Success");
            }
            catch(Exception ex)
            { MessageBox.Show(ex.Message); }
        }

        private void button18_Click(object sender, EventArgs e)
        {
            if(folderBrowserDialog1.ShowDialog()!=DialogResult.Cancel )
            {
                textBox11.Text = folderBrowserDialog1.SelectedPath;
            }

        }

        private void button17_Click(object sender, EventArgs e)
        {
            if (folderBrowserDialog1.ShowDialog() != DialogResult.Cancel)
            {
                textBox10.Text = folderBrowserDialog1.SelectedPath;
            }
        }
        

        private void checkBox1_CheckedChanged(object sender, EventArgs e)
        {
            textBox12.Enabled = checkBox1.Checked;
        }

        private void changePasswordToolStripMenuItem_Click(object sender, EventArgs e)
        {
            ChangePassword CP = new ChangePassword();
            CP.Show(this);
        }

       
        private void Form1_FormClosed_1(object sender, FormClosedEventArgs e)
        {
            Application.ExitThread();
        }

        

        private void exitToolStripMenuItem1_Click(object sender, EventArgs e)
        {
            Application.ExitThread();
        }

        private void RadioButton3_CheckedChanged(object sender, EventArgs e)
        {
            if (radioButton3.Checked == true)
            {
                TinyCode.Enabled = true;
                textBox14.Enabled = false;
               
            }
            else
            {
                TinyCode.Enabled = false;
                textBox14.Enabled = true;
            }
        }

        private void txt_DB_SelectedIndexChanged(object sender, EventArgs e)
        {

        }

        private void label6_Click(object sender, EventArgs e)
        {

        }

        private void label8_Click(object sender, EventArgs e)
        {

        }
    }
}