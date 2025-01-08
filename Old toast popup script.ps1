Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Create a form with a label, a centered logo, and a button
$form = New-Object System.Windows.Forms.Form
$form.Size = New-Object System.Drawing.Size(400, 300)  # Adjust the form size as needed.
$form.StartPosition = [System.Windows.Forms.FormStartPosition]::Manual
$form.Location = New-Object System.Drawing.Point(([System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea.Width - $form.Width), ([System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea.Height - $form.Height))
$form.TopMost = $true  # Set to true to ensure the form stays on top
$form.ControlBox = $false  # Hide the standard title bar with close, minimize, and maximize buttons

# Create a PictureBox for the logo (centered at the top)
$logoPictureBox = New-Object System.Windows.Forms.PictureBox
$logoPictureBox.Image = [System.Drawing.Image]::FromFile("C:\ProgramData\CentraStage\Brand\patchrebootwindow.png")  # Provide the path to your logo image
$logoPictureBox.Size = New-Object System.Drawing.Size($form.Width, 50)  # Adjust the width and height as needed
$logoPictureBox.Location = New-Object System.Drawing.Point(0, 0)
$logoPictureBox.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::CenterImage

$headerLabel = New-Object System.Windows.Forms.Label
$headerLabel.Text = $ENV:header_text
$headerLabel.AutoSize = $true
$headerLabel.Font = New-Object System.Drawing.Font("Arial", 12, [System.Drawing.FontStyle]::Bold)  # Set font properties as needed
$headerLabel.Location = New-Object System.Drawing.Point(([System.Math]::Round(($form.Width - $headerLabel.PreferredWidth) / 2)), 60)

$bodyLabel = New-Object System.Windows.Forms.Label
$bodyLabel.Text = $ENV:message_text
$bodyLabel.AutoSize = $false  # Set AutoSize to false as we set it static to not overlap on the button and header
$bodyLabel.Size = New-Object System.Drawing.Size(($form.Width - 20), 80)  # Set the size to accommodate the wrapped text
$bodyLabel.Font = New-Object System.Drawing.Font("Arial", $ENV:message_font_size, [System.Drawing.FontStyle]::Regular)  # Set font properties as needed
$bodyLabel.Location = New-Object System.Drawing.Point(10, 90)
$bodyLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right  # Set anchor to adjust the label size dynamically

$button = New-Object System.Windows.Forms.Button
$button.Text = "Close"
#$button.Location = New-Object System.Drawing.Point([System.Math]::Round(($form.Width - $button.Width) / 2), 190) # button position 190 px from top
$button.Location = New-Object System.Drawing.Point([System.Math]::Round(($form.Width - $button.Width) / 2), $form.Height - $button.Height - 60) #button position 60 px from bottom
$button.Add_Click({ $form.Close() })

# Add controls to the form
$form.Controls.Add($logoPictureBox)
$form.Controls.Add($headerLabel)
$form.Controls.Add($bodyLabel)
$form.Controls.Add($button)

# Show the form
$form.Add_Shown({ $form.Activate() })
$form.ShowDialog()
