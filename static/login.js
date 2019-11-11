window.onload = function() {
	var csrfInput = document.getElementById('csrf');
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
		let res = await window.fetch('/login/json', {
			method: 'post',
			headers: {
				'Content-type': 'application/json; charset=UTF-8',
				'X-CSRFToken': csrfInput.value
			},
			body: JSON.stringify({
				username: userInput.value,
				password: passInput.value
			})
		});

		if (!res.ok) {
			console.error(res);

			// TODO enable utility?
			userInput.disabled = false;
			passInput.disabled = false;
			loginBtn.disabled = false;

			let text = await res.text();
			setIssue(text === 'Forbidden' ? 'Invalid user or password' : text);
		} else if (res.redirected) {
			window.location = res.url;
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

