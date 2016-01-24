GOGETTER	:= GOPATH=$(shell pwd)/.tmpdeps go get -d

go_vendor_dependencies:
	$(GOGETTER) launchpad.net/gocheck
	echo 'removing .git from vendored pkg and moving them to vendor'
	find .tmpdeps/src -type d -name ".git" ! -name ".gitignore" -exec rm -rf {} \; || exit 0
	cp -ar .tmpdeps/src/* vendor/
	rm -rf .tmpdeps
