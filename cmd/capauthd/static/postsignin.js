(function() {
	"use strict";

	console.log("Beginning post-signin checks.");

	const fetchAndReturnWhenReady = (url) => new Promise((resolve, reject) => {
		const attemptFetch = () => {
			fetch(url)
			.then((res) => {
				if (!res.ok) throw new Error('Failed to fetch ' + url);
				return res.json();
			})
			.then((j) => {
				if (j.ok) {
					resolve();
				}
				throw new Error('Not ready yet.');
			})
			.catch((err) => {
				console.error(err);
				setTimeout(attemptFetch, 1000);
			});
		};
		attemptFetch();
	});

	Promise.all([
		fetchAndReturnWhenReady('https://v4-captive.house.as205479.net/isdone'),
		fetchAndReturnWhenReady('https://v6-captive.house.as205479.net/isdone'),
	]).then(() => {
		let nextURL = document.querySelector('meta[name="next-url"]').value;
		if (!nextURL) {
			nextURL = 'https://as205479.net';
		}
		window.location = nextURL;
	});

})();
