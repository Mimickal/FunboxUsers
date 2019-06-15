window.onload = function() {
	var userInput = document.getElementById('user');
	var passInput = document.getElementById('pass');
	var loginBtn = document.getElementById('login');
	var issueText = document.getElementById('issue');

	setIssue(null);

	loginBtn.onclick = async function() {
		// TODO disabled utility?
		userInput.disabled = true;
		passInput.disabled = true;
		loginBtn.disabled = true;

		// TODO wrap the fetch?
		let res = await window.fetch('./login', {
			method: 'post',
			headers: {
				'Content-type': 'application/json; charset=UTF-8'
			},
			body: JSON.stringify({
				username: userInput.value,
				password: passInput.value
			})
		});

		if (res.status === 200) {
			// TODO replace this with account page, obviously
			window.location = 'https://www.google.com';
		} else {
			// TODO enable utility?
			userInput.disabled = false;
			passInput.disabled = false;
			loginBtn.disabled = false;

			let text = await res.text();
			setIssue(text === 'Forbidden' ? 'Invalid user or password' : text);
		}
	};

	function setIssue(issue) {
		if (issue == null) {
			issueText.textContent = null;
			issueText.style.display = 'none';
			issueText.setAttribute('class', null);
		} else {
			issueText.textContent = issue;
			issueText.style.display = 'block';
			issueText.setAttribute('class', 'issue');
		}
	}
};

