// Функция для генерации случайных чисел в заданном диапазоне
function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

// Функция перемешивания массива (для заголовков H1-H4)
function shuffle(array) {
    for (let i = array.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [array[i], array[j]] = [array[j], array[i]];
    }
    return array;
}

// Генерация случайных параметров обфускации (как в Architect)
function randomizeAmnezia() {
    document.getElementById('jc').value = getRandomInt(3, 120);
    document.getElementById('jmin').value = getRandomInt(10, 50);
    document.getElementById('jmax').value = getRandomInt(50, 1000);
    document.getElementById('s1').value = getRandomInt(15, 150);
    document.getElementById('s2').value = getRandomInt(15, 150);

    let headers = [1, 2, 3, 4];
    headers = shuffle(headers);
    
    document.getElementById('h1').value = headers[0];
    document.getElementById('h2').value = headers[1];
    document.getElementById('h3').value = headers[2];
    document.getElementById('h4').value = headers[3];
}

// Основная функция сборки конфига
function generateAmneziaConfig() {
    let input = document.getElementById('inputConfig').value.trim();
    
    if (!input) {
        alert("Пожалуйста, вставь исходный конфиг WARP!");
        return;
    }

    // Собираем параметры Amnezia из инпутов
    const jc = document.getElementById('jc').value;
    const jmin = document.getElementById('jmin').value;
    const jmax = document.getElementById('jmax').value;
    const s1 = document.getElementById('s1').value;
    const s2 = document.getElementById('s2').value;
    const h1 = document.getElementById('h1').value;
    const h2 = document.getElementById('h2').value;
    const h3 = document.getElementById('h3').value;
    const h4 = document.getElementById('h4').value;

    const endpoint = document.getElementById('endpointSelect').value;

    // Разбиваем исходный конфиг на строки
    let lines = input.split('\n');
    let outputLines = [];

    for (let i = 0; i < lines.length; i++) {
        let line = lines[i].trim();
        
        // Перезапись эндпоинта, если выбран кастомный
        if (line.toLowerCase().startsWith('endpoint') && endpoint !== 'auto') {
            outputLines.push(`Endpoint = ${endpoint}`);
            continue;
        }

        outputLines.push(line);

        // Вставляем параметры обфускации сразу после секции [Interface]
        if (line === '[Interface]') {
            outputLines.push(`Jc = ${jc}`);
            outputLines.push(`Jmin = ${jmin}`);
            outputLines.push(`Jmax = ${jmax}`);
            outputLines.push(`S1 = ${s1}`);
            outputLines.push(`S2 = ${s2}`);
            outputLines.push(`H1 = ${h1}`);
            outputLines.push(`H2 = ${h2}`);
            outputLines.push(`H3 = ${h3}`);
            outputLines.push(`H4 = ${h4}`);
        }
    }

    // Выводим результат в нижнее текстовое поле
    document.getElementById('outputConfig').value = outputLines.join('\n');
}

// Функция копирования в буфер обмена
function copyToClipboard() {
    const output = document.getElementById('outputConfig');
    if (!output.value) return;
    
    output.select();
    document.execCommand('copy');
    alert("Конфиг скопирован в буфер обмена!");
}

// Привязываем функции к кнопкам после загрузки страницы
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('btnRandomize').addEventListener('click', randomizeAmnezia);
    document.getElementById('btnGenerate').addEventListener('click', generateAmneziaConfig);
    document.getElementById('btnCopy').addEventListener('click', copyToClipboard);
});