# makes the images... yeah

default:  pses


sliding_window.ps: sliding_window.tif
	tiff2ps -c -e sliding_window.tif > sliding_window.ps

sliding_window.pdf: sliding_window.ps
	epstopdf sliding_window.ps

pses: sliding_window.ps 
pdfes: sliding_window.pdf

clean:
	rm -rf *.ps *.pdf .xvpics
   
