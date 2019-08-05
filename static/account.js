window.onload = function() {
	var username = byId("username");

	var csrfInput = byId('csrf');

	var passRedacted = byId("pass-redacted");
	var passChangeBtn = byId("pass-change-btn");
	var passChangeForm = byId("pass-change-form");
	var passChangeCancelBtn = byId("pass-change-cancel");
	var passChangeSubmitBtn = byId("pass-change-submit");
	var passIssue = byId("pass-issue");
	var passSpinner = byId("pass-spinner");

	var passOld = document.getElementsByName("pass_old")[0];
	var passNew = document.getElementsByName("pass_new")[0];
	var passNewConf = document.getElementsByName("pass_new_conf")[0];

	var emailCurrent = byId("email-current");
	var emailNew = byId("email-new");
	var emailChangeBtn = byId("email-change-btn");
	var emailCancelBtn = byId("email-cancel-btn");
	var emailForm = byId("email-form");
	var emailSubmitBtn = byId("email-submit-btn");
	var emailIssue = byId("email-issue");
	var emailSpinner = byId("email-spinner");
	var emailConfSymbol = byId("email-conf");
	var emailUnconfSymbol = byId("email-unconf");

	var emailInput = document.getElementsByName("email_new")[0];

	var displayEmailUnconf;
	var displayEmailConf;

	// Hide forms and spinners by default
	hidePasswordForm();
	hideEmailForm();
	hide(emailConfSymbol);
	hide(emailUnconfSymbol);

	passChangeBtn.onclick = showPasswordForm;
	passChangeCancelBtn.onclick = hidePasswordForm;
	passChangeSubmitBtn.onclick = submitPassword;

	emailChangeBtn.onclick = showEmailForm;
	emailCancelBtn.onclick = hideEmailForm;
	emailSubmitBtn.onclick = submitEmail;

	// Load the logged in user's data
	window.fetch('./user').then(async function(res) {
		let data = await res.json();
		username.textContent = data.name;
		if (data.email || data.email_pending) {
			hideEmailForm();
			emailCurrent.textContent = data.email;
			emailNew.textContent = data.email_pending;
			if (data.email) {
				show(emailConfSymbol);
			}
			if (data.email_pending) {
				show(emailUnconfSymbol);
			}
		} else {
			showEmailForm();
		}
	}).catch(console.err);

	function hidePasswordForm() {
		show(passRedacted);
		show(passChangeBtn);
		hide(passChangeForm);
		hide(passSpinner);
		passIssue.textContent = "";

		clear(passOld);
		clear(passNew);
		clear(passNewConf);
	}

	function showPasswordForm() {
		hide(passRedacted);
		hide(passChangeBtn);
		show(passChangeForm);
	}

	function disablePasswordForm() {
		passNew.setAttribute("class", null);
		passNewConf.setAttribute("class", null);
		passIssue.textContent = "";

		disable(passOld);
		disable(passNew);
		disable(passNewConf);
		disable(passChangeSubmitBtn);
		disable(passChangeCancelBtn);
		show(passSpinner);
	}

	function enablePasswordForm() {
		enable(passOld);
		enable(passNew);
		enable(passNewConf);
		enable(passChangeSubmitBtn);
		enable(passChangeCancelBtn);
		hide(passSpinner);
	}

	function submitPassword() {
		passOld.setAttribute('class', null);
		passNew.setAttribute('class', null);
		passNewConf.setAttribute('class', null);
		passIssue.textContent = '';

		if (passNew.value !== passNewConf.value) {
			passNew.setAttribute("class", "issue");
			passNewConf.setAttribute("class", "issue");
			passIssue.textContent = "Passwords don't match!"
		}
		else if (passNew.value === "") {
			passNew.setAttribute("class", "issue");
			passNewConf.setAttribute("class", "issue");
			passIssue.textContent = "New password is empty!";
		}
		else {
			disablePasswordForm();
			window.fetch('./update/password', {
				method: 'put',
				headers: {
					'Content-type': 'application/json; charset=UTF-8',
					'X-CSRFToken': csrfInput.value
				},
				body: JSON.stringify({
					pass_old: passOld.value,
					pass_new: passNew.value,
					pass_new_conf: passNewConf.value
				})
			})
			.then(async function(res) {
				if (res.ok) {
					hidePasswordForm();
					enablePasswordForm();
					passRedacted.textContent = "Password updated";
					passRedacted.setAttribute("class", "green");
				} else {
					issue = await res.text();
					if (issue === 'Old password incorrect') {
						enablePasswordForm();
						passOld.setAttribute('class', 'issue');
					}
					passIssue.textContent = issue;
				}
			})
			.catch(function(err) {
				enablePasswordForm();
				passIssue.textContent = err;
			});
		}
	}

	function hideEmailForm() {
		hide(emailSpinner);
		hide(emailForm);
		enable(emailInput);
		enable(emailSubmitBtn);
		enable(emailCancelBtn);
		show(emailChangeBtn);
		show(emailCurrent);
		show(emailNew);
		clear(emailInput);
		emailIssue.textContent = "";

		emailUnconfSymbol.style.display = displayEmailUnconf;
		emailConfSymbol.style.display = displayEmailConf;
	}

	function showEmailForm() {
		hide(emailCurrent);
		hide(emailNew);
		hide(emailChangeBtn);
		show(emailForm);

		// Flask will determine if these are shown by default
		displayEmailConf = emailConfSymbol.style.display;
		displayEmailUnconf = emailUnconfSymbol.style.display;

		hide(emailUnconfSymbol);
		hide(emailConfSymbol);
	}

	function disableEmailForm() {
		emailInput.setAttribute("class", null);
		disable(emailInput);
		disable(emailSubmitBtn);
		disable(emailCancelBtn);
		show(emailSpinner);
	}

	function enableEmailForm() {
		enable(emailInput);
		enable(emailSubmitBtn);
		enable(emailCancelBtn);
		hide(emailSpinner);
	}

	function submitEmail() {
		if (validEmail(emailInput.value)) {
			disableEmailForm();
			emailIssue.textContent = "";

			post('./', {
				email: emailInput.value
			}).then(function(res) {
				hideEmailForm();
				emailCurrent.textContent = res.email_new;

				// Both change symbols and override default display modes
				hide(emailConfSymbol);
				show(emailUnconfSymbol);
				displayEmailConf = "none";
				displayEmailUnconf = "block";
			}).catch(function(err) {
				enableEmailForm();
				emailIssue.textContent = err;
			});
		} else {
			emailInput.setAttribute("class", "issue");
			emailIssue.textContent = "Invalid email";
		}
	}

};

// Shamelessly stolen from
// https://tylermcginnis.com/validate-email-address-javascript/
var EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
function validEmail(email) {
	return EMAIL_REGEX.test(email);
}

// TODO for browser native form backwards compatibility,
// we may want to do 'x-www-form-urlencoded' instead.
// TODO also, polyfill for old browsers
// Should send with cookie named fb_session
function post(url, data) {
	return window.fetch(url, {
		method: 'post',
		headers: {
			"Content-type": 'application/json; charset=UTF-8'
		},
		body: JSON.stringify(data)
	});
}

// HELPERS
// Abstract away all the nitty-gritty things
function byId(id) {
	return document.getElementById(id);
}

function hide(elem) {
	elem.style.display = "none";
}

function show(elem) {
	elem.style.display = "block";
}

function clear(field) {
	field.value = "";
	field.setAttribute("class", null);
}

function disable(elem) {
	elem.disabled = true;
}

function enable(elem) {
	elem.disabled = false;
}
