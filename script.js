function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function shuffle(array) {
    for (let i = array.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [array[i], array[j]] = [array[j], array[i]];
    }
    return array;
}

function randomizeAmnezia() {
    document.getElementById('jc').value = getRandomInt(3, 120);
    document.getElementById('jmin').value = getRandomInt(10, 50);
    document.getElementById('jmax').value = getRandomInt(50, 1000);
    document.getElementById('s1').value = getRandomInt(15, 150);
    document.getElementById('s2').value = getRandomInt(15, 150);

    let headers = shuffle([1, 2, 3, 4]);
    document.getElementById('h1').value = headers[0];
    document.getElementById('h2').value = headers[1];
    document.getElementById('h3').value = headers[2];
    document.getElementById('h4').value = headers[3];
}

function generateAmneziaConfig() {
    const input = document.getElementById('inputConfig').value.trim();
    
    if (!input) {
        alert("Вставьте исходный конфиг WARP (WireGuard)!");
        return;
    }
    if (!input.includes('[Interface]') || !input.includes('[Peer]')) {
        alert("Неверный формат конфига! Убедитесь, что есть секции [Interface] и [Peer].");
        return;
    }

    const params = {
        Jc: document.getElementById('jc').value,
        Jmin: document.getElementById('jmin').value,
        Jmax: document.getElementById('jmax').value,
        S1: document.getElementById('s1').value,
        S2: document.getElementById('s2').value,
        H1: document.getElementById('h1').value,
        H2: document.getElementById('h2').value,
        H3: document.getElementById('h3').value,
        H4: document.getElementById('h4').value
    };

    const endpoint = document.getElementById('endpointSelect').value;

    let lines = input.split('\n');
    let outputLines = [];
    let inInterface = false;

    for (let i = 0; i < lines.length; i++) {
        let line = lines[i].trim();
        
        // Заменяем эндпоинт
        if (line.toLowerCase().startsWith('endpoint') && endpoint !== 'auto') {
            outputLines.push(`Endpoint = ${endpoint}`);
            continue;
        }

        outputLines.push(line);

        // Инжектим параметры обфускации
        if (line === '[Interface]') {
            for (const [key, value] of Object.entries(params)) {
                outputLines.push(`${key} = ${value}`);
            }
        }
    }

    document.getElementById('outputConfig').value = outputLines.join('\n');
}

function copyToClipboard() {
    const output = document.getElementById('outputConfig');
    if (!output.value) return;
    
    output.select();
    navigator.clipboard.writeText(output.value).then(() => {
        const toast = document.getElementById('toast');
        toast.classList.add('show');
        setTimeout(() => toast.classList.remove('show'), 2000);
    });
}

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('btnRandomize').addEventListener('click', randomizeAmnezia);
    document.getElementById('btnGenerate').addEventListener('click', generateAmneziaConfig);
    document.getElementById('btnCopy').addEventListener('click', copyToClipboard);
    
    // Сгенерировать параметры при загрузке страницы
    randomizeAmnezia();
});
