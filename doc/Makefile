all: slides.pdf documentation.pdf

documentation.tex: documentation.lhs
	lhs2TeX documentation.lhs -o documentation.tex

documentation.pdf: documentation.tex bibliography.bib lat1.pdf lat2.pdf
	pdflatex documentation.tex -halt-on-error -output-directory=./out/; bibtex documentation; pdflatex documentation.tex -halt-on-error -output-directory=./out/

slides.tex: slides.lhs
	lhs2TeX slides.lhs -o slides.tex

slides.pdf: slides.tex bibliography.bib
	pdflatex slides.tex -halt-on-error -output-directory=./out/; bibtex slides; pdflatex documentation.tex -halt-on-error -output-directory=./out/

clean:
	rm *.tex *.toc *.log *.nav *.out *.snm *.aux *.bbl *.blg *.pdfsync documentation.pdf slides.pdf
 
