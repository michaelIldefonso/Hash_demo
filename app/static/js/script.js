document.getElementById("login-form").addEventListener("submit", async function(event) {
    event.preventDefault();

    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;

    try {
        const response = await fetch("/login", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ email: email, password: password })
        });

        const result = await response.json();

        if (result.token) {
            // Store token in localStorage
            localStorage.setItem("authToken", result.token);
            alert("Login successful! Token saved.");
            
            // Redirect to a protected page or homepage
            window.location.href = "/protected";
        } else {
            alert("Login failed: Invalid credentials");
        }
    } catch (error) {
        console.error("Error logging in:", error);
        alert("An error occurred while logging in.");
    }
});

async function testToken() {
    const token = localStorage.getItem("authToken");  // Retrieve the token from localStorage
    if (!token) {
        alert("No token found. Please log in.");
        return;
    }

    try {
        const response = await fetch("/protected", {
            method: "GET",
            headers: {
                "Authorization": token  // Add the token in the Authorization header
            }
        });

        if (response.ok) {
            const data = await response.json();
            alert("Token is valid: " + JSON.stringify(data));
        } else {
            const errorData = await response.json();
            alert("Token is invalid: " + errorData.message);
        }
    } catch (error) {
        console.error("Error testing token:", error);
        alert("An error occurred while testing the token.");
    }
}

// Check if the token is stored in cookies or localStorage
function checkToken() {
    const token = localStorage.getItem('auth_token');  // Or check cookies if you're storing it there

    if (!token) {
        // If no token, redirect to login page
        window.location.href = '/login';
        return;
    }

    // Optionally, make an API call to validate the token on the server
    fetch('/check_session', {
        method: 'GET',
        headers: {
            'Authorization': `Bearer ${token}`
        }
    }).then(response => {
        if (response.status === 401) {
            // Token is expired or invalid
            window.location.href = '/login';  // Redirect to login page
        } else {
            // Token is valid, show the content
            console.log('User is authenticated');
        }
    }).catch(error => {
        console.log('Error checking token:', error);
        window.location.href = '/login';  // Redirect on error (e.g., network issue)
    });
}

// Call the function to check the token when the page loads
checkToken();