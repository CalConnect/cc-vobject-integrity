MMARK:=mmark -xml2 -page
MMARK3:=mmark -xml -page

# md_objects := $(patsubst %.md,%.md.txt,$(wildcard *.md))
# exclude_objects := README.md
# target_objects := $(filter-out $(exclude_objects),$(md_objects))
#all: $(target_objects)

objects := $(patsubst %.md,%.md.txt,$(wildcard *.md))
objectsv3xml := $(patsubst %.md,%.md.3.xml,$(wildcard *.md))
all: $(objects)

%.md.txt: %.md
	$(MMARK) $< > $<.xml
	xml2rfc --text $<.xml && rm $<.xml

%.md.2.xml: %.md
	$(MMARK) $< > $<.2.xml

%.md.3.xml: %.md
	$(MMARK3) $< > $<.3.xml

.PHONY: clean
clean:
	rm -f *.md.txt *md.[23].xml

