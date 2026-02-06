const API_BASE_URL = '/api';
const authPages = document.getElementById('auth-pages');
const appLayout = document.getElementById('app-layout');
const loginForm = document.getElementById('login-form');
const registerForm = document.getElementById('register-form');
const showRegisterLink = document.getElementById('show-register');
const showLoginLink = document.getElementById('show-login');
const loginSubmitBtn = document.getElementById('login-submit');
const registerSubmitBtn = document.getElementById('register-submit');
const logoutBtn = document.getElementById('logout-btn');
const hamburger = document.querySelector('.hamburger');
const sidebar = document.querySelector('.sidebar');
const menuItems = document.querySelectorAll('.menu-item');
const pages = document.querySelectorAll('.page');
const pageTitle = document.getElementById('page-title');
const notificationContainer = document.getElementById('notification-container');

let authToken = null;
let currentUser = null;
let masterKey = null;
let currentView = 'passwords';

document.addEventListener('DOMContentLoaded',  () => {
    const storedUser = localStorage.getItem('currentUser');
    if (authToken != null && currentUser != null) {
        authToken = null;
        currentUser = JSON.parse(storedUser);
        showApp();
    } else {
        showAuth();
    }
    setupEventListeners();
});
function setupEventListeners() {
    showRegisterLink.addEventListener('click', (e) => {
        e.preventDefault();
        showRegisterForm();
    });
    showLoginLink.addEventListener('click', (e) => {
        e.preventDefault();
        showLoginForm();
    });
    loginSubmitBtn.addEventListener('click', handleLogin);
    registerSubmitBtn.addEventListener('click', handleRegister);
    logoutBtn.addEventListener('click', logout);
    hamburger.addEventListener('click', (e) => {
        e.stopPropagation();
        sidebar.classList.toggle('active');
    });
    document.addEventListener('click', (e) => {
        if (window.innerWidth <= 768 &&
            !sidebar.contains(e.target) &&
            e.target !== hamburger &&
            sidebar.classList.contains('active')) {
            sidebar.classList.remove('active');
        }
    });
    menuItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const targetPage = item.getAttribute('data-page');
            showPage(targetPage);
            if (window.innerWidth <= 768) {
                sidebar.classList.remove('active');
            }
        });
    });
    window.addEventListener('resize', () => {
        if (window.innerWidth > 768) {
            sidebar.classList.add('active');
        } else if (!sidebar.classList.contains('active')) {
            hamburger.classList.remove('hidden');
        }
    });
    document.getElementById('search-input').addEventListener('input', filterPasswords);
    document.getElementById('add-password-form').addEventListener('submit', handleAddPassword);
    document.getElementById('generate-password-btn').addEventListener('click', () => {
        document.getElementById('new-password').value = generateStrongPassword();
    });
    document.getElementById('trust-current-device-btn').addEventListener('click', trustCurrentDevice);
}
function showAuth() {
    authPages.style.display = 'flex';
    appLayout.style.display = 'none';
}
function showApp() {
    authPages.style.display = 'none';
    appLayout.style.display = 'flex';
    const userAvatar = document.querySelector('.user-avatar');
    const profileAvatar = document.querySelector('.profile-avatar');
    if(!currentUser){
        userAvatar.textContent = '.';
        profileAvatar.textContent = '.';
    }
    else{
        const username = currentUser.username;
        userAvatar.textContent = username[0];
        profileAvatar.textContent = username[0];
    }
    updateUserInterface();
    loadPasswords();
    loadTrustedDevices();
    loadDeviceHistory();
    loadFavorites();
}
function showLoginForm() {
    loginForm.style.display = 'block';
    registerForm.style.display = 'none';
}
function showRegisterForm() {
    loginForm.style.display = 'none';
    registerForm.style.display = 'block';
}
async function handleLogin() {
    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;

    if (!username || !password) {
        showNotification('Пожалуйста, заполните все поля', 'error');
        return;
    }

    masterKey = password;
    const hashedPassword = await hashPasswordWithSalt(password, username);

    document.getElementById('login-text').style.display = 'none';
    document.getElementById('login-loading').style.display = 'inline-block';
    loginSubmitBtn.disabled = true;
    try {
        const response = await fetch(`${API_BASE_URL}/auth/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username:username,
                password:hashedPassword,
                deviceInfo: getDeviceInfo()
            })
        });
        const data = await response.json();
        if (response.ok) {
            authToken = data.token;
            currentUser = data.user;
            localStorage.setItem('currentUser', JSON.stringify(currentUser));
            showApp();
            showNotification('Успешный вход!', 'success');
        } else {
            showNotification('Ошибка входа. Проверьте данные.', 'error');
        }
    } catch (error) {
        console.error('Login error:', error);
    } finally {
        document.getElementById('login-text').style.display = 'inline';
        document.getElementById('login-loading').style.display = 'none';
        loginSubmitBtn.disabled = false;
    }
}
async function handleRegister() {
    const username = document.getElementById('register-username').value;
    const password = document.getElementById('register-password').value;
    const confirmPassword = document.getElementById('register-confirm-password').value;
    if (!username || !password || !confirmPassword) {
        showNotification('Пожалуйста, заполните все поля', 'error');
        return;
    }
    if (password !== confirmPassword) {
        showNotification('Пароли не совпадают', 'error');
        return;
    }
    if (password.length < 6) {
        showNotification('Пароль должен быть не менее 6 символов', 'error');
        return;
    }
    masterKey = password;
    const hashedPassword = await hashPasswordWithSalt(password, username);
    
    document.getElementById('register-text').style.display = 'none';
    document.getElementById('register-loading').style.display = 'inline-block';
    registerSubmitBtn.disabled = true;
    try {
        const response = await fetch(`${API_BASE_URL}/auth/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username:username,
                password: hashedPassword,
            })
        });
        const data = await response.json();
        if (response.ok) {
            authToken = data.token;
            currentUser = data.user;
            localStorage.setItem('currentUser', JSON.stringify(currentUser));
            showApp();
            showNotification('Регистрация успешна!', 'success');
        } else {
            showNotification('Пользователь уже существует', 'error');
        }
    } catch (error) {
        showNotification('Ошибка подключения к серверу', 'error');
    } finally {
        document.getElementById('register-text').style.display = 'inline';
        document.getElementById('register-loading').style.display = 'none';
        registerSubmitBtn.disabled = false;
    }
}

async function hashPasswordWithSalt(password, username) {
    const encoder = new TextEncoder();
    const saltBuffer = encoder.encode(username);
    const dataToHash = encoder.encode(password + username); 
    const key = await window.crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveBits"]
    );
    const derivedBits = await window.crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt: saltBuffer,
            iterations: 600000,
            hash: "SHA-256"
        },
        key,
        256 
    );
    const hashArray = Array.from(new Uint8Array(derivedBits));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
}
function logout() {
    authToken = null;
    currentUser = null;
    localStorage.removeItem('currentUser');
    showAuth();
    showNotification('Вы вышли из системы', 'success');
}
function showPage(pageName) {
    menuItems.forEach(item => {
        item.classList.toggle('active', item.getAttribute('data-page') === pageName);
    });
    pages.forEach(page => {
        page.classList.toggle('active', page.id === `${pageName}-page`);
    });
    const titles = {
        'passwords': 'Мои пароли',
        'favorites': 'Избранные пароли',
        'devices': 'Устройства',
        'settings': 'Настройки'
    };
    pageTitle.textContent = titles[pageName] || 'Менеджер паролей';
    currentView = pageName;
    if (pageName === 'devices') {
        loadTrustedDevices();
        loadDeviceHistory();
    }
    if (pageName === 'passwords') {
        loadPasswords();
    }
    if (pageName === 'favorites') {
        loadFavorites();
    }
}
function updateUserInterface() {
    if (currentUser) {
        document.getElementById('sidebar-username').textContent = currentUser.username;
        document.getElementById('profile-username').textContent = currentUser.username;
        document.getElementById('update-username').value = currentUser.username;
    }
}
async function loadPasswords() {
    try {
        const response = await fetch(`${API_BASE_URL}/passwords`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });

        if (response.ok) {
            const encryptedPasswords = await response.json();
            let decryptedPasswords = [];
            for (const item of encryptedPasswords) {
                try {
                    let decrypted_username = await decryptData(item.username, masterKey);
                    let decrypted_password = await decryptData(item.password, masterKey);
                    let decrypted_service = await decryptData(item.service, masterKey);
                    decryptedPasswords.push({
                        id: item.id,
                        password: decrypted_password,
                        service: decrypted_service,
                        username: decrypted_username
                    });
                } catch (e) {
                    continue;
                }
            }

            renderPasswordList(decryptedPasswords);
        } else {
            const error = await response.json();
            if (response.status === 401) {
                logout();
            } else {
                showNotification(`Ошибка загрузки:`, 'error');
            }
        }
    } catch (error) {
        showNotification('Ошибка загрузки паролей', 'error');
    }
}
async function loadFavorites() {
    try {
        const response = await fetch(`${API_BASE_URL}/passwords/favorites`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        if (response.ok) {
            const data = await response.json();
    const favoritesFormatted = [];
    
    for (const fp of data.favorite_passwords) {
        try {
            let decrypted_username = await decryptData(fp.username, masterKey);
            let decrypted_service = await decryptData(fp.service_name, masterKey);
            favoritesFormatted.push({
                id: fp.password_id,
                service: decrypted_service,
                username: decrypted_username,
                password: "", 
                favorite: true
            });
        } catch (e) {
            continue;
        }
    }
    
    renderFavoritesList(favoritesFormatted);
        } else {
            const error = await response.json();
            if (response.status === 401) {
                logout();
            } else {
                showNotification(`Ошибка загрузки избранного`, 'error');
            }
        }
    } catch (error) {
        showNotification('Ошибка загрузки избранного', 'error');
    }
}
async function loadTrustedDevices() {
    try {
        const response = await fetch(`${API_BASE_URL}/devices/trusted`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        if (response.ok) {
            const data = await response.json();
            renderTrustedDevicesList(data.devices);
        } else {
            const error = await response.json();
            if (response.status === 401) {
                logout();
            } else {
                showNotification(`Ошибка загрузки доверенных устройств: ${error.error}`, 'error');
            }
        }
    } catch (error) {
        showNotification('Ошибка загрузки доверенных устройств', 'error');
    }
}
async function loadDeviceHistory() {
    try {
        const response = await fetch(`${API_BASE_URL}/devices/history`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        if (response.ok) {
            const data = await response.json();
            renderDeviceHistoryList(data.history);
        } else {
            const error = await response.json();
            if (response.status === 401) {
                logout();
            } else {
                showNotification(`Ошибка загрузки истории устройств`, 'error');
            }
        }
    } catch (error) {
        console.error('Load device history error:', error);
        showNotification('Ошибка загрузки истории устройств', 'error');
    }
}
async function handleAddPassword(e) {
    e.preventDefault();
    const service = document.getElementById('new-service').value;
    const username = document.getElementById('new-username').value;
    const password = document.getElementById('new-password').value;
    if (!service || !username || !password) {
        showNotification('Пожалуйста, заполните все поля', 'error');
        return;
    }
    
    try {
        const encryptedService = await encryptData(service, masterKey);
        const encryptedUsername = await encryptData(username, masterKey);
        const encryptedPassword = await encryptData(password, masterKey);
        const response = await fetch(`${API_BASE_URL}/passwords`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({ 
                service: encryptedService, 
                username: encryptedUsername, 
                password: encryptedPassword 
            })
        });
        if (response.ok) {
            document.getElementById('add-password-form').reset();
            showNotification('Пароль добавлен!', 'success');
            loadPasswords();
            if (currentView !== 'passwords') {
                showPage('passwords');
            }
        } else {
            const error = await response.json();
            showNotification(`Ошибка добавления пароля`, 'error');
        }
    } catch (error) {
        showNotification('Ошибка добавления пароля', 'error');
    }
}
async function deletePassword(id) {
    try {
        const response = await fetch(`${API_BASE_URL}/passwords/${id}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        if (response.ok) {
            showNotification('Пароль удален!', 'success');
            loadPasswords();
        } else {
            const error = await response.json();
            if (response.status === 401) {
                logout();
            } else {
                showNotification(`Ошибка удаления пароля`, 'error');
            }
        }
    } catch (error) {
        showNotification('Ошибка удаления пароля', 'error');
    }
}
async function toggleFavorite(id, favorite) {
    let success = false;
    if (favorite) {
        success = await addToFavorites(id);
    } else {
        success = await removeFromFavorites(id);
    }
    if (success) {
        const btn = document.querySelector(`.favorite-btn[data-id="${id}"]`);
        if (btn) {
            btn.innerHTML = favorite ? '<span class="material-symbols-outlined">cancel</span>' : '<span class="material-symbols-outlined">star</span>';
            btn.setAttribute('data-fav', favorite);
        }
    }
}
async function addToFavorites(passwordId) {
    try {
        const response = await fetch(`${API_BASE_URL}/passwords/favorites`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({ password_id: passwordId })
        });
        if (response.ok) {
            const data = await response.json();
            showNotification('Пароль добавлен в избранное!', 'success');
            if (currentView === 'favorites') {
                loadFavorites();
            } else if (currentView === 'passwords') {
                loadPasswords();
            }
            return true;
        } else {
            const error = await response.json();
            if (response.status === 401) {
                logout();
            } else if (response.status === 409) {
                showNotification('Пароль уже в избранном', 'error');
            } else {
                showNotification(`Ошибка добавления в избранное`, 'error');
            }
            return false;
        }
    } catch (error) {
        showNotification('Ошибка добавления в избранное', 'error');
        return false;
    }
}
async function removeFromFavorites(passwordId) {
    try {
        const response = await fetch(`${API_BASE_URL}/passwords/favorites/${passwordId}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        if (response.ok) {
            const data = await response.json();
            showNotification('Пароль удален из избранного', 'success');
            if (currentView === 'favorites') {
                loadFavorites();
            } else if (currentView === 'passwords') {
                loadPasswords();
            }
            return true;
        } else {
            const error = await response.json();
            if (response.status === 401) {
                logout();
            } else {
                showNotification(`Ошибка удаления из избранного`, 'error');
            }
            return false;
        }
    } catch (error) {
        showNotification('Ошибка удаления из избранного', 'error');
        return false;
    }
}
async function removeTrustedDevice(id) {
    try {
        const response = await fetch(`${API_BASE_URL}/devices/trusted/${id}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        if (response.ok) {
            showNotification('Устройство удалено из доверенных!', 'success');
            loadTrustedDevices();
        } else {
            const error = await response.json();
            if (response.status === 401) {
                logout();
            } else if (response.status === 404) {
                showNotification('Устройство не найдено или доступ запрещен', 'error');
            } else {
                showNotification(`Ошибка`, 'error');
            }
        }
    } catch (error) {
        showNotification('Ошибка удаления устройства из доверенных', 'error');
    }
}
async function trustCurrentDevice() {
    try {
        const deviceInfo = getDeviceInfo();
        const response = await fetch(`${API_BASE_URL}/devices/trust-current`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({ deviceInfo })
        });
        if (response.ok) {
            showNotification('Текущее устройство добавлено в доверенные!', 'success');
            loadTrustedDevices();
        } else {
            const error = await response.json();
            if (response.status === 401) {
                logout();
            } else if (response.status === 409) {
                showNotification('Устройство уже доверенное', 'error');
            } else {
                showNotification(`Ошибка`, 'error');
            }
        }
    } catch (error) {
        showNotification('Ошибка добавления устройства в доверенные', 'error');
    }
}
function getDeviceInfo() {
    const ua = navigator.userAgent;
    let browserName = 'Unknown';
    let browserVersion = 'Unknown';
    let osName = 'Unknown';
    let osVersion = 'Unknown';
    let deviceType = 'Desktop';
    let deviceName = 'Unknown';
    if (ua.indexOf('Firefox') > -1) {
        browserName = 'Firefox';
        browserVersion = ua.match(/Firefox\/([0-9.]+)/)?.[1] || 'Unknown';
    } else if (ua.indexOf('Chrome') > -1) {
        browserName = 'Chrome';
        browserVersion = ua.match(/Chrome\/([0-9.]+)/)?.[1] || 'Unknown';
    } else if (ua.indexOf('Safari') > -1) {
        browserName = 'Safari';
        browserVersion = ua.match(/Version\/([0-9.]+)/)?.[1] || 'Unknown';
    } else if (ua.indexOf('Edge') > -1) {
        browserName = 'Edge';
        browserVersion = ua.match(/Edge\/([0-9.]+)/)?.[1] || 'Unknown';
    }
    if (ua.indexOf('Windows NT 10.0') > -1) {
        osName = 'Windows';
        osVersion = '10';
    } else if (ua.indexOf('Windows NT 6.3') > -1) {
        osName = 'Windows';
        osVersion = '8.1';
    } else if (ua.indexOf('Mac OS X') > -1) {
        osName = 'macOS';
        osVersion = ua.match(/Mac OS X ([0-9_.]+)/)?.[1]?.replace(/_/g, '.') || 'Unknown';
    } else if (ua.indexOf('Android') > -1) {
        osName = 'Android';
        osVersion = ua.match(/Android ([0-9.]+)/)?.[1] || 'Unknown';
        deviceType = 'Mobile';
    } else if (ua.indexOf('iPhone') > -1 || ua.indexOf('iPad') > -1) {
        osName = 'iOS';
        osVersion = ua.match(/OS ([0-9_]+)/)?.[1]?.replace(/_/g, '.') || 'Unknown';
        deviceType = ua.indexOf('iPad') > -1 ? 'Tablet' : 'Mobile';
    }
    if (/mobile|android|iphone|ipod/i.test(ua)) {
        deviceType = 'Mobile';
    } else if (/tablet|ipad/i.test(ua)) {
        deviceType = 'Tablet';
    } else {
        deviceType = 'Desktop';
    }
    if (deviceType === 'Mobile') {
        deviceName = 'Mobile Device';
    } else if (deviceType === 'Tablet') {
        deviceName = 'Tablet Device';
    } else {
        deviceName = 'Desktop Computer';
    }
    return {
        browserName,
        browserVersion,
        osName,
        osVersion,
        deviceType,
        deviceName
    };
}
function filterPasswords() {
    const query = document.getElementById('search-input').value.toLowerCase();
    const passwordList = document.getElementById('password-list');
    const items = passwordList.querySelectorAll('.list-item');
    items.forEach(item => {
        const service = item.querySelector('.item-title').textContent.toLowerCase();
        const username = item.querySelector('.item-subtitle').textContent.toLowerCase();
        if (service.includes(query) || username.includes(query)) {
            item.style.display = '';
        } else {
            item.style.display = 'none';
        }
    });
}
function generateStrongPassword() {
    const length = 14;
    const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
    let password = "";
    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * charset.length);
        password += charset[randomIndex];
    }
    return password;
}
function formatDate(dateString) {
    if (!dateString) return 'Неизвестно';
    const date = new Date(dateString);
    if (isNaN(date.getTime())) {
        return dateString;
    }
    return date.toLocaleString('ru-RU', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
}
function showNotification(message, type) {
    const notification = document.createElement('div');
    notification.className = `notification ${type} show`;
    notification.textContent = message;
    notificationContainer.appendChild(notification);
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => {
            if (notification.parentNode) {
                notification.remove();
            }
        }, 300);
    }, 3000);
}
function renderPasswordList(passwords) {
    const passwordList = document.getElementById('password-list');
    passwordList.innerHTML = '';
    if (passwords.length === 0) {
        passwordList.innerHTML = '<li class="list-item"><div class="item-info"><div class="item-title">Нет сохраненных паролей</div></div></li>';
        return;
    }
    passwords.forEach(p => {
        const li = document.createElement('li');
        li.className = 'list-item';
        const hiddenPassword = '••••••••';
        li.innerHTML = `
<div class="item-info">
<div class="item-title">${p.service}</div>
<div class="item-subtitle">${p.username}</div>
<div>
<span class="password-hidden" id="password-${p.id}">${hiddenPassword}</span>
<button class="reveal-btn" data-id="${p.id}" data-password="${p.password}"><span class="material-symbols-outlined">visibility</span></button></button>
</div>
</div>
<div class="item-actions">
<button class="btn-icon btn-secondary copy-btn" data-password="${p.password}" title="Копировать">
<span class="material-symbols-outlined">content_copy</span>
</button>
<button class="btn-icon btn-warning favorite-btn" data-id="${p.id}" data-fav="false" title="Добавить в избранное">
<span class="material-symbols-outlined">star</span>
</button>
<button class="btn-icon btn-danger delete-btn" data-id="${p.id}" title="Удалить">
<span class="material-symbols-outlined">delete</span>
</button>
</div>
`;
        passwordList.appendChild(li);
    });
    attachPasswordItemListeners();
}
function renderFavoritesList(favorites) {
    const favoritesList = document.getElementById('favorites-list');
    favoritesList.innerHTML = '';
    if (favorites.length === 0) {
        favoritesList.innerHTML = '<li class="list-item"><div class="item-info"><div class="item-title">Нет избранных паролей</div></div></li>';
        return;
    }
    favorites.forEach(p => {
        const li = document.createElement('li');
        li.className = 'list-item';
        li.innerHTML = `
<div class="item-info">
<div class="item-title">${p.service}</div>
<div class="item-subtitle">${p.username}</div>
</div>
<div class="item-actions">
<button class="btn-icon btn-secondary copy-btn" data-password="${p.password}" title="Копировать">
<span class="material-symbols-outlined">content_copy</span>
</button>
<button class="btn-icon btn-warning favorite-btn" data-id="${p.id}" data-fav="true" title="Убрать из избранного">
<span class="material-symbols-outlined">cancel</span>
</button>
</div>
`;
        favoritesList.appendChild(li);
    });
    attachPasswordItemListeners();
}
function renderTrustedDevicesList(devices) {
    const trustedDevicesList = document.getElementById('trusted-devices-list');
    trustedDevicesList.innerHTML = '';
    if (devices.length === 0) {
        trustedDevicesList.innerHTML = '<li class="list-item"><div class="item-info"><div class="item-title">Нет доверенных устройств</div></div></li>';
        return;
    }
    devices.forEach(d => {
        const li = document.createElement('li');
        li.className = 'list-item';
        li.innerHTML = `
<div class="item-info">
<div class="item-title">${d.device_name  || 'Неизвестное устройство'}</div>
<div class="item-subtitle">${d.os_name} ${d.os_version}, ${d.browser_name} ${d.browser_version}</div>
<div class="item-subtitle">ID: ${d.id}</div>
<div class="item-subtitle">Последний вход: ${formatDate(d.last_seen_at)}</div>
<div class="item-subtitle">Дата добавления: ${formatDate(d.created_at)}</div>
</div>
<div class="item-actions">
<button class="btn-icon btn-danger untrust-device-btn" data-id="${d.id}" title="Удалить из доверенных">
<span class="material-symbols-outlined">delete</span>
</button>
</div>
`;
        trustedDevicesList.appendChild(li);
    });
    attachTrustedDeviceItemListeners();
}
function renderDeviceHistoryList(history) {
    const historyList = document.getElementById('history-list');
    historyList.innerHTML = '';
    if (history.length === 0) {
        historyList.innerHTML = '<li class="list-item"><div class="item-info"><div class="item-title">История входов пуста</div></div></li>';
        return;
    }
    history.forEach(h => {
        const li = document.createElement('li');
        li.className = 'list-item';
        li.innerHTML = `
<div class="item-info">
<div class="item-title">${h.device_name || 'Неизвестное устройство'}</div>
<div class="item-subtitle">${h.os_name} ${h.os_version}, ${h.browser_name} ${h.browser_version}</div>
<div class="item-subtitle">ID: ${h.id}</div>
<div class="item-subtitle">Вход: ${formatDate(h.created_at)}</div>
<div class="item-subtitle">Последний визит: ${formatDate(h.last_seen_at)}</div>
<div class="item-subtitle">Активно: ${h.is_active ? 'Да' : 'Нет'}</div>
</div>
`;
        historyList.appendChild(li);
    });
}
function attachPasswordItemListeners() {
    document.querySelectorAll('.reveal-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const id = e.currentTarget.getAttribute('data-id');
            const password = e.currentTarget.getAttribute('data-password');
            const passwordSpan = document.getElementById(`password-${id}`);
            const icon = e.currentTarget.querySelector('.material-symbols-outlined');
            if (passwordSpan.textContent.includes('•')) {
                passwordSpan.textContent = password;
                icon.textContent = 'visibility_off';
            } else {
                passwordSpan.textContent = '••••••••';
                icon.textContent = 'visibility';
            }
        });
    });
    document.querySelectorAll('.copy-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const password = e.currentTarget.getAttribute('data-password');
            navigator.clipboard.writeText(password).then(() => {
                showNotification('Пароль скопирован!', 'success');
            }).catch(() => {
                showNotification('Не удалось скопировать пароль', 'error');
            });
        });
    });
    document.querySelectorAll('.favorite-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const id = e.currentTarget.getAttribute('data-id');
            const isFav = e.currentTarget.getAttribute('data-fav') === 'true';
            toggleFavorite(id, !isFav);
        });
    });
    document.querySelectorAll('.delete-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const id = e.currentTarget.getAttribute('data-id');
            if (confirm('Удалить этот пароль?')) {
                deletePassword(id);
            }
        });
    });
}
function attachTrustedDeviceItemListeners() {
    document.querySelectorAll('.untrust-device-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const id = e.currentTarget.getAttribute('data-id');
            if (confirm('Удалить это устройство из доверенных?')) {
                removeTrustedDevice(id);
            }
        });
    });
}

async function encryptData(data, masterKey) {
    const encoder = new TextEncoder();
    const salt = crypto.getRandomValues(new Uint8Array(16)); 
    const iv = crypto.getRandomValues(new Uint8Array(12)); 

    const key = await generateKey(masterKey, salt);

    const encryptedContent = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encoder.encode(data)
    );
    const result = new Uint8Array(salt.length + iv.length + encryptedContent.byteLength);
    result.set(salt, 0);
    result.set(iv, salt.length);
    result.set(new Uint8Array(encryptedContent), salt.length + iv.length);
    const binString = String.fromCodePoint(...result);
    return btoa(binString); 
}

async function decryptData(encryptedBase64, masterKey) {
    const sanitized = encryptedBase64.replace(/\s/g, '');
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(sanitized)) {
        throw new Error("Invalid base64 string");
    }

    const binString = atob(sanitized);
    const combined = Uint8Array.from(binString, (char) => char.codePointAt(0));
    const salt = combined.slice(0, 16);   
    const iv = combined.slice(16, 16 + 12); 
    const data = combined.slice(16 + 12); 

    const key = await generateKey(masterKey, salt);

    const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        key,
        data
    );

    const decoder = new TextDecoder();
    return decoder.decode(decrypted); 
}


async function generateKey(masterKey, salt) {
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(masterKey);

    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        passwordBuffer,
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );

    return await crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}
