This is the repository for a burp extension called `cartogradur` which is used to dig out vulnerable mapping api keys from web sites.

This is still very much a work in progress so if something changes or breaks don't be too surprised.  Once it's stable and has additional functionality I will remove this warning :)

## Why does this exist?

Good question, this was born out of the world of bug bounties.  I got tired of looking, and searching for, API keys so put together a quick PoC burp plugin to do the job for me.  This is my first Burp plugin, and I don't really write much Java so if something could be better I am always open to a pull request :)

## Danger, Will Robinson!

I caution you right now, some people will not consider this a real issue while others will. You need to make sure that you really know the programs you are hacking on before submitting this.  If you don't then it is very easy to end up getting an `Informative` or `N/A` if people do not fully understand the actual financial impact of this type of issue.

## If You Trust Me

1. Add the provided `cartogradur.jar` file to your Burp extensions
2. ???
3. Profit

## Build Instructions

1. Git clone it locally to some dir
2. cd into that some dir

3-linux. Run the following bash one liner: 
```
javac -d build src/burp/*.java && \
cd build && \
jar cvf cartogradur.jar burp/*.class && \
mv cartogradur.jar ../ && \
cd ../ && \
rm -rf build
```

3.-windows. Run the following
```
javac -target 8 -source 8 -d build src/burp/*.java
cd build
jar cvf cartogradur.jar burp/*.class
mv cartogradur.jar ../
cd ../
rm  build
```
4. Add the newly built `cartogradur.jar` file to your Burp extensions
5. ???
6. Profit
