from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4

# Create a canvas
c = canvas.Canvas("data/sigpage.pdf",pagesize=A4)
width, height = c._pagesize
print(width, height)

# Add text
c.drawString(20, 766, "This is the signature page for a verifiable pdf")


# Add an image
c.drawImage("data/qrimage.png", 300, 550, 256,256)

# Save the PDF
c.save()
