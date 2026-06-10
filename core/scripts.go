package core

const DYNAMIC_REDIRECT_JS = `
function getRedirect(sid) {
	var url = "/s/" + sid;
	console.log("fetching: " + url);
	fetch(url, {
		method: "GET",
		headers: {
			"Content-Type": "application/json"
		},
		credentials: "include"
	})
		.then((response) => {

			if (response.status == 200) {
				return response.json();
			} else if (response.status == 408) {
				console.log("timed out");
				getRedirect(sid);
			} else {
				throw "http error: " + response.status;
			}
		})
		.then((data) => {
			if (data !== undefined) {
				console.log("api: success:", data);
				top.location.href=data.redirect_url;
			}
		})
		.catch((error) => {
			console.error("api: error:", error);
			setTimeout(function () { getRedirect(sid) }, 10000);
		});
}
getRedirect('{session_id}');
`
