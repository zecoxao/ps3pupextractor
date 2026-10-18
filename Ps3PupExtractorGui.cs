// ps3pupextractor GUI - PlayStation 3 firmware (PUP) unpacker + full explode.
// WinForms, .NET Framework 4.x. Build with csc /target:winexe.
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Threading;
using System.Windows.Forms;

namespace Ps3PupExtractor
{
    public class MainForm : Form
    {
        TextBox txtPup, txtOut, txtLog;
        Button btnPup, btnOut, btnExtract, btnBatch;
        CheckBox chkExplode, chkDevFlash, chkVerify;
        ProgressBar progress;
        Label lblStatus;

        public MainForm()
        {
            Text = "PS3 PUP Extractor";
            ClientSize = new Size(760, 520);
            MinimumSize = new Size(600, 420);
            Font = new Font("Segoe UI", 9f);
            StartPosition = FormStartPosition.CenterScreen;
            AllowDrop = true;
            DragEnter += (s, e) => { if (e.Data.GetDataPresent(DataFormats.FileDrop)) e.Effect = DragDropEffects.Copy; };
            DragDrop += (s, e) => { var f = (string[])e.Data.GetData(DataFormats.FileDrop); if (f != null && f.Length > 0) SetPup(f[0]); };

            var lblPup = new Label { Text = "PUP file:", Left = 12, Top = 15, Width = 70 };
            txtPup = new TextBox { Left = 85, Top = 12, Width = 560, Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right };
            btnPup = new Button { Text = "Browse...", Left = 651, Top = 10, Width = 95, Anchor = AnchorStyles.Top | AnchorStyles.Right };
            btnPup.Click += (s, e) => BrowsePup();

            var lblOut = new Label { Text = "Output:", Left = 12, Top = 47, Width = 70 };
            txtOut = new TextBox { Left = 85, Top = 44, Width = 560, Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right };
            btnOut = new Button { Text = "Browse...", Left = 651, Top = 42, Width = 95, Anchor = AnchorStyles.Top | AnchorStyles.Right };
            btnOut.Click += (s, e) => BrowseOut();

            chkExplode = new CheckBox { Text = "Full explode (decrypt SELF→ELF, unpkg, cosunpkg)", Left = 85, Top = 74, Width = 360, Checked = true };
            chkExplode.CheckedChanged += (s, e) => chkDevFlash.Enabled = chkExplode.Checked;
            chkDevFlash = new CheckBox { Text = "Include dev_flash (large)", Left = 85, Top = 98, Width = 220, Checked = false };
            chkVerify = new CheckBox { Text = "Verify HMAC", Left = 320, Top = 98, Width = 130, Checked = true };

            btnExtract = new Button { Text = "Extract", Left = 545, Top = 72, Width = 95, Height = 26, Anchor = AnchorStyles.Top | AnchorStyles.Right };
            btnExtract.Click += (s, e) => StartSingle();
            btnBatch = new Button { Text = "Batch...", Left = 651, Top = 72, Width = 95, Height = 26, Anchor = AnchorStyles.Top | AnchorStyles.Right };
            btnBatch.Click += (s, e) => StartBatch();

            txtLog = new TextBox
            {
                Left = 12, Top = 130, Width = 734, Height = 352,
                Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false,
                Font = new Font("Consolas", 9f), BackColor = Color.FromArgb(24, 24, 24), ForeColor = Color.Gainsboro,
                Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right
            };
            progress = new ProgressBar { Left = 12, Top = 490, Width = 600, Height = 20, Style = ProgressBarStyle.Blocks, Anchor = AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right };
            lblStatus = new Label { Left = 620, Top = 492, Width = 126, Text = "Ready", Anchor = AnchorStyles.Bottom | AnchorStyles.Right };

            Controls.AddRange(new Control[] { lblPup, txtPup, btnPup, lblOut, txtOut, btnOut,
                chkExplode, chkDevFlash, chkVerify, btnExtract, btnBatch, txtLog, progress, lblStatus });
        }

        void BrowsePup()
        {
            using (var dlg = new OpenFileDialog())
            {
                dlg.Filter = "PS3 update package (*.pup;*.PUP)|*.pup;*.PUP|All files (*.*)|*.*";
                if (dlg.ShowDialog(this) == DialogResult.OK) SetPup(dlg.FileName);
            }
        }
        void SetPup(string path)
        {
            txtPup.Text = path;
            if (txtOut.Text.Length == 0)
                txtOut.Text = Path.Combine(Path.GetDirectoryName(path), Path.GetFileNameWithoutExtension(path) + "_extracted");
        }
        void BrowseOut()
        {
            using (var dlg = new FolderBrowserDialog())
            { dlg.Description = "Choose output folder"; if (dlg.ShowDialog(this) == DialogResult.OK) txtOut.Text = dlg.SelectedPath; }
        }

        void Log(string s) { if (txtLog.InvokeRequired) { txtLog.BeginInvoke((Action<string>)Log, s); return; } txtLog.AppendText(s + "\r\n"); }
        void SetStatus(string s) { if (lblStatus.InvokeRequired) { lblStatus.BeginInvoke((Action<string>)SetStatus, s); return; } lblStatus.Text = s; }
        void SetBusy(bool busy)
        {
            if (InvokeRequired) { BeginInvoke((Action<bool>)SetBusy, busy); return; }
            btnExtract.Enabled = btnBatch.Enabled = btnPup.Enabled = btnOut.Enabled = txtPup.Enabled = txtOut.Enabled =
                chkExplode.Enabled = chkVerify.Enabled = !busy;
            chkDevFlash.Enabled = !busy && chkExplode.Checked;
            progress.Style = busy ? ProgressBarStyle.Marquee : ProgressBarStyle.Blocks;
            if (!busy) progress.Value = 0;
            UseWaitCursor = busy;
        }

        void StartSingle()
        {
            string pup = txtPup.Text.Trim(), outDir = txtOut.Text.Trim();
            if (pup.Length == 0 || !File.Exists(pup)) { MessageBox.Show(this, "Select a valid PUP file."); return; }
            if (outDir.Length == 0) { outDir = Path.Combine(Path.GetDirectoryName(pup), Path.GetFileNameWithoutExtension(pup) + "_extracted"); txtOut.Text = outDir; }
            bool explode = chkExplode.Checked, dev = chkDevFlash.Checked, verify = chkVerify.Checked;
            txtLog.Clear(); SetBusy(true); SetStatus("Working...");
            RunThread(() => RunOne(pup, outDir, explode, dev, verify));
        }

        void StartBatch()
        {
            // 1. pick the input folder containing the PUPs
            string inDir;
            using (var dlg = new FolderBrowserDialog())
            {
                dlg.Description = "Choose the folder containing the PUP files to process";
                if (dlg.ShowDialog(this) != DialogResult.OK) return;
                inDir = dlg.SelectedPath;
            }

            // 2. output folder must be set (each PUP -> <out>\<name>_extracted)
            string parent = txtOut.Text.Trim();
            if (parent.Length == 0 || File.Exists(parent))
            {
                using (var dlg = new FolderBrowserDialog())
                {
                    dlg.Description = "Choose the output folder for all extracted PUPs";
                    if (dlg.ShowDialog(this) != DialogResult.OK) return;
                    parent = dlg.SelectedPath; txtOut.Text = parent;
                }
            }

            // 3. gather every *.pup in the input folder (case-insensitive on Windows)
            var list = new List<string>();
            try
            {
                foreach (string f in Directory.GetFiles(inDir, "*.pup", SearchOption.TopDirectoryOnly))
                    list.Add(f);
            }
            catch (Exception ex) { MessageBox.Show(this, "Cannot read folder: " + ex.Message); return; }
            list.Sort(StringComparer.OrdinalIgnoreCase);
            if (list.Count == 0) { MessageBox.Show(this, "No .pup files found in:\n" + inDir); return; }

            {
                string[] files = list.ToArray();
                bool explode = chkExplode.Checked, dev = chkDevFlash.Checked, verify = chkVerify.Checked;
                txtLog.Clear(); SetBusy(true); SetStatus("Batch...");
                Log(string.Format("Batch: {0} PUP(s) from {1}\n  -> {2}", files.Length, inDir, parent));
                RunThread(() =>
                {
                    int ok = 0, fail = 0;
                    for (int i = 0; i < files.Length; i++)
                    {
                        string f = files[i];
                        string outDir = Path.Combine(parent, Path.GetFileNameWithoutExtension(f) + "_extracted");
                        Log(string.Format("\n===== [{0}/{1}] {2} =====", i + 1, files.Length, Path.GetFileName(f)));
                        SetStatus(string.Format("Batch {0}/{1}", i + 1, files.Length));
                        try { if (explode) Exploder.Explode(f, outDir, dev, Log); else Pup.Split(f, outDir, verify, Log); ok++; }
                        catch (Exception ex) { Log("  ERROR: " + ex.Message); fail++; }
                    }
                    Log(string.Format("\nBatch done. OK={0} FAIL={1}", ok, fail));
                    Done(fail == 0);
                });
            }
        }

        void RunOne(string pup, string outDir, bool explode, bool dev, bool verify)
        {
            try
            {
                if (explode) Exploder.Explode(pup, outDir, dev, Log);
                else { Pup.Split(pup, outDir, verify, Log); Log("\nDone (container split)."); }
                Done(true);
            }
            catch (Exception ex) { Log("\nERROR: " + ex.Message); Done(false); }
        }

        void RunThread(ThreadStart work) { var t = new Thread(work); t.IsBackground = true; t.Start(); }
        void Done(bool ok) { SetBusy(false); SetStatus(ok ? "Done" : "Finished with errors"); }

        [STAThread]
        static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            var f = new MainForm();
            if (args.Length >= 1) f.Shown += (s, e) => f.SetPup(args[0]);
            Application.Run(f);
        }
    }
}
